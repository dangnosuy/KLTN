import json
import tempfile
import unittest
from pathlib import Path

from pipeline.multi_agent.algorithm import (
    MultiAgentConfig,
    MultiAgentRunner,
    PLANNER_SYSTEM,
    CODER_SYSTEM,
    REVIEWER_SYSTEM,
)
from pipeline.single_agent.__main__ import detector_success


def feedback(detected: bool):
    return {
        "build": "PASSED",
        "detectors": {
            "ember": {
                "status": "COMPLETED",
                "detected": detected,
                "score": 0.85 if detected else 0.25,
            }
        },
    }


class QueueModel:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, system, user, temperature):
        self.calls.append((system, user, temperature))
        if not self.responses:
            raise RuntimeError("QueueModel ran out of mocked responses")
        return self.responses.pop(0)


class MultiAgentTests(unittest.TestCase):
    def test_invalid_config(self):
        with self.assertRaises(ValueError):
            MultiAgentConfig(max_attempts=-1)
        with self.assertRaises(ValueError):
            MultiAgentConfig(target="")

    def test_baseline_already_passed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            output = root / "output"

            model = QueueModel([])
            runner = MultiAgentRunner(
                model,
                lambda _p: (0.8, feedback(False)),
                detector_success("ember"),
                MultiAgentConfig(max_attempts=3),
            )
            result = runner.run(source, output)
            self.assertTrue(result["success"])
            self.assertEqual(result["attempt_count"], 0)
            self.assertEqual(len(model.calls), 0)
            self.assertTrue((output / "best.c").is_file())

    def test_multi_agent_three_role_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            output = root / "output"

            # Round 1:
            # 1. Planner outputs plan
            # 2. Coder outputs candidate
            # 3. Reviewer outputs APPROVED
            responses = [
                "Plan: apply string hashing and obfuscate main flow.",
                "```c\nint main(void) { /* evasive */ return 0; }\n```",
                "VERDICT: APPROVED\nCRITIQUE: Code is valid and preserves return 0.",
            ]
            model = QueueModel(responses)

            call_count = 0
            def evaluate(path):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    # baseline evaluation on input.c
                    return 0.3, feedback(True)
                # candidate evaluation
                return 0.85, feedback(False)

            runner = MultiAgentRunner(
                model,
                evaluate,
                detector_success("ember"),
                MultiAgentConfig(max_attempts=3),
            )
            result = runner.run(source, output)

            self.assertTrue(result["success"])
            self.assertEqual(result["attempt_count"], 1)
            self.assertEqual(len(model.calls), 3)
            # Verify system prompts matched the roles
            self.assertEqual(model.calls[0][0], PLANNER_SYSTEM)
            self.assertEqual(model.calls[1][0], CODER_SYSTEM)
            self.assertEqual(model.calls[2][0], REVIEWER_SYSTEM)

            # Check log files
            self.assertTrue((output / "plans.jsonl").is_file())
            self.assertTrue((output / "reviews.jsonl").is_file())
            self.assertTrue((output / "attempts.jsonl").is_file())
            self.assertTrue((output / "best.c").is_file())
            self.assertIn("/* evasive */", (output / "best.c").read_text())

    def test_reviewer_critique_triggers_refinement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            output = root / "output"

            # Round 1:
            # 1. Planner
            # 2. Coder initial
            # 3. Reviewer: CHANGES_REQUESTED
            # 4. Coder refinement
            responses = [
                "Plan: flatten loop.",
                "```c\nint main(void) { int x = ; return 0; }\n```",
                "VERDICT: CHANGES_REQUESTED\nCRITIQUE: Syntax error: int x = ; missing value",
                "```c\nint main(void) { int x = 0; return 0; }\n```",
            ]
            model = QueueModel(responses)

            call_count = 0
            def evaluate(path):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return 0.2, feedback(True)
                return 0.9, feedback(False)

            runner = MultiAgentRunner(
                model,
                evaluate,
                detector_success("ember"),
                MultiAgentConfig(max_attempts=2, reviewer_refinement=True),
            )
            result = runner.run(source, output)

            self.assertTrue(result["success"])
            self.assertEqual(result["attempt_count"], 1)
            self.assertEqual(len(model.calls), 4)
            self.assertIn("int x = 0;", (output / "best.c").read_text())

    def test_parse_review_heuristics(self):
        v1, c1 = MultiAgentRunner._parse_review("Changes requested. Remove decode_payload function.")
        self.assertEqual(v1, "CHANGES_REQUESTED")
        self.assertIn("Remove decode_payload", c1)

        v2, c2 = MultiAgentRunner._parse_review("Approved. Everything looks good and functional.")
        self.assertEqual(v2, "APPROVED")

        v3, c3 = MultiAgentRunner._parse_review("VERDICT: PASS\nCRITIQUE: Clean code.")
        self.assertEqual(v3, "APPROVED")

    def test_reviewer_critique_in_next_planner_prompt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            output = root / "output"

            # Attempt 1: Planner -> Coder -> Reviewer (Approved) -> Evaluator fails
            # Attempt 2: Planner (should have critique) -> Coder -> Reviewer -> Evaluator passes
            responses = [
                "Plan 1",
                "```c\nint main(void) { return 1; }\n```",
                "VERDICT: APPROVED\nCRITIQUE: Valid syntax but check return value.",
                "Plan 2",
                "```c\nint main(void) { return 0; }\n```",
                "VERDICT: APPROVED\nCRITIQUE: Corrected.",
            ]
            model = QueueModel(responses)

            call_count = 0
            def evaluate(path):
                nonlocal call_count
                call_count += 1
                if call_count <= 2:
                    return 0.3, feedback(True)
                return 0.9, feedback(False)

            runner = MultiAgentRunner(
                model,
                evaluate,
                detector_success("ember"),
                MultiAgentConfig(max_attempts=2, reviewer_refinement=False),
            )
            result = runner.run(source, output)
            self.assertTrue(result["success"])
            self.assertEqual(result["attempt_count"], 2)

            # Check that Attempt 2 Planner received critique from Attempt 1
            attempt2_planner_prompt = model.calls[3][1]
            self.assertIn("Valid syntax but check return value", attempt2_planner_prompt)


if __name__ == "__main__":
    unittest.main()
