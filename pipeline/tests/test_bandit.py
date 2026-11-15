import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pipeline.bandit.algorithm import BanditConfig, BanditRunner
from pipeline.bandit.__main__ import detector_success


class FakePool:
    operators = {"alpha": object(), "beta": object()}

    def transform(self, source, genes, destination):
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(",".join(gene.operator for gene in genes), encoding="utf-8")
        return [{"operator": gene.operator, "seed": gene.seed} for gene in genes]


def completed(success):
    return {"build": "PASSED", "detectors": {"ember": {"status": "COMPLETED", "detected": not success}}}


class BanditTests(unittest.TestCase):
    def test_target_detector_result_controls_binary_reward(self):
        success = detector_success("ember")
        self.assertTrue(success(completed(True)))
        self.assertFalse(success(completed(False)))
        with self.assertRaises(ValueError):
            success({"detectors": {}})

    def test_success_is_minimized_and_essential_arm_is_rewarded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.c"
            source.write_text("int main(void) { return 0; }", encoding="utf-8")
            runner = BanditRunner(FakePool(), lambda path: (1.0 if path.read_text() else 0.0, completed(bool(path.read_text()))), lambda details: not details["detectors"]["ember"]["detected"], "ember", BanditConfig(query_budget=4, seed=3))
            with patch.object(runner, "_select", return_value=(runner.arms["alpha"], 0.9)):
                result = runner.run(source, root / "output")
            self.assertTrue(result["success"])
            self.assertEqual(result["minimized_genes"][0]["operator"], "alpha")
            self.assertEqual(result["arms"]["alpha"]["alpha"], 2)
            self.assertTrue((root / "output" / "minimized.c").is_file())
            self.assertEqual(len((root / "output" / "evaluations.jsonl").read_text().splitlines()), 2)

    def test_failures_increment_beta_until_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.c"
            source.write_text("int main(void) { return 0; }", encoding="utf-8")
            runner = BanditRunner(FakePool(), lambda _path: (0.2, completed(False)), lambda _details: False, "ember", BanditConfig(query_budget=3, max_actions=2, seed=4))
            with patch.object(runner, "_select", return_value=(runner.arms["beta"], 0.8)):
                result = runner.run(source, root / "output")
            self.assertFalse(result["success"])
            self.assertEqual(result["evaluations"], 3)
            self.assertEqual(result["arms"]["beta"]["beta"], 4)
            self.assertEqual(result["arms"]["beta"]["pulls"], 3)
            self.assertEqual(len(json.loads((root / "output" / "result.json").read_text())["arms"]), 2)


if __name__ == "__main__":
    unittest.main()
