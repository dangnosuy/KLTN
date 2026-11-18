import json
import tempfile
import unittest
from pathlib import Path

from pipeline.ga_only.algorithm import GAConfig
from pipeline.hybrid_fixed.algorithm import FixedHybridConfig, FixedHybridRunner, parse_llm_heuristic


class FakePool:
    operators = {"alpha": object(), "beta": object()}

    def transform(self, source, genes, destination):
        destination.parent.mkdir(parents=True, exist_ok=True)
        active = [gene for gene in genes if gene.operator != "noop"]
        destination.write_text(source.read_text(encoding="utf-8") + "\n/* " + ",".join(gene.operator for gene in active) + " */\n", encoding="utf-8")
        return [{"operator": gene.operator, "seed": gene.seed} for gene in active]


class FakeModel:
    def __init__(self):
        self.calls = []

    def __call__(self, system, prompt, temperature):
        self.calls.append((system, prompt, temperature))
        seed = len(self.calls)
        return json.dumps({
            "thought": f"LLM heuristic {seed}",
            "genes": [
                {"operator": "alpha", "seed": seed},
                {"operator": "beta", "seed": seed + 10},
            ],
        })


class FixedHybridTests(unittest.TestCase):
    def test_parser_accepts_only_pool_genes(self):
        thought, genes = parse_llm_heuristic(
            '{"thought":"try alpha","genes":[{"operator":"alpha","seed":7}]} trailing',
            {"alpha"},
            1,
        )
        self.assertEqual(thought, "try alpha")
        self.assertEqual(genes[0].operator, "alpha")
        with self.assertRaisesRegex(ValueError, "unknown operator"):
            parse_llm_heuristic('{"thought":"x","genes":[{"operator":"new","seed":1}]}', {"alpha"}, 1)
        with self.assertRaisesRegex(ValueError, "initial population"):
            FixedHybridConfig(ga=GAConfig(population_size=4, tournament_size=2, max_evaluations=3))

    def test_fixed_llm_quota_runs_every_generation_without_stagnation_stop(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            model = FakeModel()

            def evaluate(candidate):
                text = candidate.read_text(encoding="utf-8")
                return text.count("alpha"), {"build": "PASSED"}

            ga = GAConfig(
                population_size=4,
                generations=2,
                chromosome_length=2,
                tournament_size=2,
                max_evaluations=12,
                seed=3,
            )
            result = FixedHybridRunner(
                FakePool(),
                evaluate,
                model,
                FixedHybridConfig(ga=ga, llm_fraction=0.25, parent_count=2),
            ).run(source, root / "output")

            self.assertEqual(len(model.calls), 3)  # initialization + one fixed call per generation
            self.assertEqual([item["generation"] for item in result["history"]], [0, 1, 2])
            self.assertEqual([item["strategy"] for item in map(json.loads, (root / "output" / "llm_heuristics.jsonl").read_text().splitlines())], ["I", "E1", "E2"])
            self.assertTrue((root / "output" / "best.c").is_file())
            self.assertEqual(result["fixed_llm_offspring"], 1)
            self.assertEqual(result["baseline"], "hybrid-fixed-eoh")

    def test_invalid_llm_output_is_logged_and_replaced_by_ga_candidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            ga = GAConfig(population_size=2, generations=1, chromosome_length=1, tournament_size=1, max_evaluations=4)
            result = FixedHybridRunner(
                FakePool(),
                lambda _candidate: (0.1, {"build": "PASSED"}),
                lambda *_args: "not json",
                FixedHybridConfig(ga=ga, llm_fraction=0.5),
            ).run(source, root / "output")
            records = [json.loads(line) for line in (root / "output" / "llm_heuristics.jsonl").read_text().splitlines()]
            self.assertEqual([record["status"] for record in records], ["ERROR", "ERROR"])
            self.assertEqual(result["llm_calls"], 2)


if __name__ == "__main__":
    unittest.main()
