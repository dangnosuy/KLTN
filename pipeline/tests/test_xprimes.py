import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pipeline.xprimes.algorithm import XPriMESConfig, XPriMESRunner
from pipeline.xprimes.__main__ import detector_success


class FakePool:
    operators = {"alpha": object(), "beta": object()}

    def transform(self, source, genes, destination):
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(",".join(gene.operator for gene in genes), encoding="utf-8")
        return [{"operator": gene.operator, "seed": gene.seed} for gene in genes]


def completed(success, score=0.8):
    return {
        "build": "PASSED",
        "detectors": {
            "ember": {
                "status": "COMPLETED",
                "detected": not success,
                "score": score,
            }
        },
    }


class XPriMESTests(unittest.TestCase):
    def test_target_detector_success_predicate(self):
        success = detector_success("ember")
        self.assertTrue(success(completed(True)))
        self.assertFalse(success(completed(False)))
        with self.assertRaises(ValueError):
            success({"detectors": {}})

    def test_dense_reward_and_prioritized_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.c"
            source.write_text("int main(void) { return 0; }", encoding="utf-8")

            scores = [0.9, 0.7, 0.4]  # successive drops -> dense rewards
            call_count = 0

            def eval_fn(_path):
                nonlocal call_count
                score = scores[min(call_count, len(scores) - 1)]
                call_count += 1
                return 1.0 - score, completed(score < 0.5, score=score)

            runner = XPriMESRunner(
                FakePool(),
                eval_fn,
                lambda details: not details["detectors"]["ember"]["detected"],
                "ember",
                XPriMESConfig(query_budget=5, seed=42),
            )
            result = runner.run(source, root / "output")
            self.assertTrue(result["success"])
            self.assertGreater(result["replay_buffer_size"], 0)
            self.assertTrue((root / "output" / "best.c").is_file())
            self.assertTrue((root / "output" / "minimized.c").is_file())

    def test_exhaust_budget_without_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.c"
            source.write_text("int main(void) { return 0; }", encoding="utf-8")

            runner = XPriMESRunner(
                FakePool(),
                lambda _path: (0.1, completed(False, score=0.9)),
                lambda _details: False,
                "ember",
                XPriMESConfig(query_budget=4, max_actions=2, seed=7),
            )
            result = runner.run(source, root / "output")
            self.assertFalse(result["success"])
            self.assertEqual(result["evaluations"], 4)
            self.assertIsNone(result["minimized_source"])
            self.assertTrue((root / "output" / "best.c").is_file())


if __name__ == "__main__":
    unittest.main()
