import json
import tempfile
import unittest
from pathlib import Path

from pipeline.random_search.algorithm import RandomSearchConfig, RandomSearchRunner
from pipeline.random_search.__main__ import detector_success


class FakePool:
    operators = {"flatten": object(), "split": object(), "encode_arithmetic": object()}

    def transform(self, source, genes, destination):
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(",".join(gene.operator for gene in genes), encoding="utf-8")
        return [{"operator": gene.operator, "seed": gene.seed} for gene in genes]


def completed(success: bool):
    return {"build": "PASSED", "detectors": {"ember": {"status": "COMPLETED", "detected": not success}}}


class RandomSearchTests(unittest.TestCase):
    def test_detector_success(self):
        success = detector_success("ember")
        self.assertTrue(success(completed(True)))
        self.assertFalse(success(completed(False)))
        with self.assertRaises(ValueError):
            success({"detectors": {}})

    def test_invalid_config(self):
        with self.assertRaises(ValueError):
            RandomSearchConfig(query_budget=-1)
        with self.assertRaises(ValueError):
            RandomSearchConfig(min_actions=5, max_actions=2)

    def test_random_search_exhausts_budget_without_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.c"
            source.write_text("int main(void) { return 0; }", encoding="utf-8")
            output = root / "output"

            runner = RandomSearchRunner(
                FakePool(),
                lambda _path: (0.4, completed(False)),
                lambda details: not details["detectors"]["ember"]["detected"],
                "ember",
                RandomSearchConfig(query_budget=3, min_actions=1, max_actions=2, seed=42),
            )
            result = runner.run(source, output)
            self.assertFalse(result["success"])
            self.assertEqual(result["evaluations"], 3)
            self.assertTrue((output / "best.c").is_file())
            self.assertTrue((output / "result.json").is_file())
            lines = (output / "evaluations.jsonl").read_text().strip().splitlines()
            self.assertEqual(len(lines), 3)

    def test_random_search_stops_early_on_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.c"
            source.write_text("int main(void) { return 0; }", encoding="utf-8")
            output = root / "output"

            # Succeed on 2nd attempt
            call_count = 0
            def eval_func(_path):
                nonlocal call_count
                call_count += 1
                is_win = (call_count == 2)
                return (0.9 if is_win else 0.3, completed(is_win))

            runner = RandomSearchRunner(
                FakePool(),
                eval_func,
                lambda details: not details["detectors"]["ember"]["detected"],
                "ember",
                RandomSearchConfig(query_budget=10, min_actions=1, max_actions=2, seed=42, stop_on_success=True),
            )
            result = runner.run(source, output)
            self.assertTrue(result["success"])
            self.assertEqual(result["evaluations"], 2)
            self.assertEqual(call_count, 2)

    def test_reproducible_with_seed(self):
        config1 = RandomSearchConfig(query_budget=5, seed=12345)
        config2 = RandomSearchConfig(query_budget=5, seed=12345)
        runner1 = RandomSearchRunner(FakePool(), lambda _p: (0.5, completed(False)), lambda _d: False, "ember", config1)
        runner2 = RandomSearchRunner(FakePool(), lambda _p: (0.5, completed(False)), lambda _d: False, "ember", config2)

        genes1 = [runner1._sample_genes() for _ in range(5)]
        genes2 = [runner2._sample_genes() for _ in range(5)]
        self.assertEqual(genes1, genes2)


if __name__ == "__main__":
    unittest.main()
