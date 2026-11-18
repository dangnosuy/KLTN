import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pipeline.ga_only.algorithm import GAConfig, GARunner
from pipeline.ga_only.__main__ import command_evaluator
from pipeline.ga_only.operators import Gene, TigressPool
from pipeline.ga_only.static_score import score_source


def write_pool(root):
    path = root / "pool.json"
    path.write_text(json.dumps({
        "binary": "tigress",
        "environment": "x86_64:Linux:Gcc:4.6",
        "driver_args": ["--Compiler=x86_64-w64-mingw32-gcc"],
        "functions": ["main"],
        "operators": [{"name": "flatten", "args": ["--Transform=Flatten", "--Functions={functions}"]}],
    }), encoding="utf-8")
    return TigressPool.load(path)


class FakePool:
    operators = {"alpha": object(), "beta": object()}

    def transform(self, source, genes, destination):
        active = [gene for gene in genes if gene.operator != "noop"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(source.read_text(encoding="utf-8") + "\n/* " + ",".join(gene.operator + str(gene.seed) for gene in active) + " */\n", encoding="utf-8")
        return [{"operator": gene.operator, "seed": gene.seed} for gene in active]


class GAOnlyTests(unittest.TestCase):
    def test_score_command_expands_home_directory(self):
        completed = subprocess.CompletedProcess([], 0, '{"fitness": 0.5}', "")
        with patch("pipeline.ga_only.__main__.subprocess.run", return_value=completed) as invoked:
            fitness, _ = command_evaluator("~/venv/bin/python {source}")(Path("candidate.c"))
        self.assertEqual(fitness, 0.5)
        self.assertEqual(invoked.call_args.args[0][0], str(Path("~/venv/bin/python").expanduser()))

    def test_pool_runs_tigress_chain(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.c"
            output = root / "output.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            pool = write_pool(root)

            def run(command, **kwargs):
                output_arg = next(arg for arg in command if arg.startswith("--out="))
                Path(output_arg.split("=", 1)[1]).write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
                return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()

            with patch("pipeline.ga_only.operators.subprocess.run", side_effect=run) as invoked:
                trace = pool.transform(source, (Gene("flatten", 7),), output)
            self.assertTrue(output.is_file())
            self.assertEqual(trace[0]["operator"], "flatten")
            self.assertIn("--Seed=7", invoked.call_args.args[0])
            self.assertIn("--Functions=main", invoked.call_args.args[0])
            self.assertIn("--Compiler=x86_64-w64-mingw32-gcc", invoked.call_args.args[0])

    def test_ga_writes_candidates_best_and_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.c"
            output = root / "run"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")

            def evaluate(candidate):
                text = candidate.read_text(encoding="utf-8")
                return text.count("alpha"), {"status": "PASSED"}

            config = GAConfig(population_size=4, generations=2, chromosome_length=3, tournament_size=2, max_evaluations=12, seed=4)
            result = GARunner(FakePool(), evaluate, config).run(source, output)
            self.assertTrue((output / "best.c").is_file())
            self.assertTrue((output / "result.json").is_file())
            self.assertTrue(list((output / "candidates").glob("generation-*/*.c")))
            self.assertEqual(result["best_fitness"], (output / "best.c").read_text(encoding="utf-8").count("alpha"))
            self.assertLessEqual(result["evaluations"], 12)

    def test_invalid_pool_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "pool.json"
            path.write_text('{"binary": "tigress"}', encoding="utf-8")
            with self.assertRaises(ValueError):
                TigressPool.load(path)

    def test_static_score_compiles_and_combines_clamav_with_ember(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")

            def compile_candidate(command, **kwargs):
                self.assertIn("-Wl,--no-insert-timestamp", command)
                Path(command[-1]).write_bytes(b"MZ test")
                return subprocess.CompletedProcess(command, 0, "", "")

            def scan(_scanner, engine, _artifact):
                if engine == "ember":
                    return {"status": "COMPLETED", "verdict": "NO_ALERT", "detected": False, "score": 0.2, "threshold": 0.5}
                return {"status": "COMPLETED", "verdict": "NO_ALERT", "detected": False, "threat_names": []}

            with patch("pipeline.ga_only.static_score.shutil.which", return_value="compiler"), \
                 patch("pipeline.ga_only.static_score.subprocess.run", side_effect=compile_candidate), \
                 patch("pipeline.ga_only.static_score.StaticScanner.scan", new=scan):
                result = score_source(source)

            self.assertEqual(result["build"], "PASSED")
            self.assertAlmostEqual(result["fitness"], 0.9)
            self.assertEqual(result["detectors"]["ember"]["score"], 0.2)

    def test_static_score_compiles_and_combines_three_engines(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")

            def compile_candidate(command, **kwargs):
                Path(command[-1]).write_bytes(b"MZ test")
                return subprocess.CompletedProcess(command, 0, "", "")

            def scan(_scanner, engine, _artifact):
                if engine == "ember":
                    return {"status": "COMPLETED", "verdict": "NO_ALERT", "detected": False, "score": 0.2, "threshold": 0.5}
                if engine == "malconv":
                    return {"status": "COMPLETED", "verdict": "NO_ALERT", "detected": False, "score": 0.1, "threshold": 0.5}
                return {"status": "COMPLETED", "verdict": "NO_ALERT", "detected": False, "threat_names": []}

            with patch("pipeline.ga_only.static_score.shutil.which", return_value="compiler"), \
                 patch("pipeline.ga_only.static_score.subprocess.run", side_effect=compile_candidate), \
                 patch("pipeline.ga_only.static_score.StaticScanner.scan", new=scan):
                result = score_source(source, engines=("clamav", "ember", "malconv"))

            self.assertEqual(result["build"], "PASSED")
            # (1.0 + 0.8 + 0.9) / 3 = 0.9
            self.assertAlmostEqual(result["fitness"], 0.9)
            self.assertEqual(result["detectors"]["malconv"]["score"], 0.1)

    def test_static_score_compiles_and_combines_with_cape(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")

            def compile_candidate(command, **kwargs):
                Path(command[-1]).write_bytes(b"MZ test")
                return subprocess.CompletedProcess(command, 0, "", "")

            def scan_static(_scanner, engine, _artifact):
                if engine == "ember":
                    return {"status": "COMPLETED", "verdict": "NO_ALERT", "detected": False, "score": 0.2, "threshold": 0.5}
                return {"status": "COMPLETED", "verdict": "NO_ALERT", "detected": False, "threat_names": []}

            def scan_cape(_scanner, _sample, _directory):
                return {"status": "COMPLETED", "verdict": "NO_ALERT", "detected": False, "score": 1.0, "threshold": 4.0}

            with patch("pipeline.ga_only.static_score.shutil.which", return_value="compiler"), \
                 patch("pipeline.ga_only.static_score.subprocess.run", side_effect=compile_candidate), \
                 patch("pipeline.ga_only.static_score.StaticScanner.scan", new=scan_static), \
                 patch("pipeline.detectors.cape.CapeScanner.scan", new=scan_cape):
                result = score_source(source, engines=("clamav", "ember", "cape"))

            self.assertEqual(result["build"], "PASSED")
            # clamav: 1.0, ember: 0.8, cape: 1.0 - (1.0 / 10.0) = 0.9 -> (1.0 + 0.8 + 0.9) / 3 = 0.9
            self.assertAlmostEqual(result["fitness"], 0.9)
            self.assertEqual(result["detectors"]["cape"]["score"], 1.0)


if __name__ == "__main__":
    unittest.main()
