import json
import tempfile
import unittest
from pathlib import Path

from pipeline.single_agent.__main__ import detector_success
from pipeline.single_agent.algorithm import ReflexionConfig, ReflexionRunner, extract_c_code


def feedback(detected):
    return {
        "build": "PASSED",
        "detectors": {
            "ember": {
                "status": "COMPLETED",
                "detected": detected,
                "score": 0.8 if detected else 0.2,
            }
        },
    }


class QueueModel:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, system, user, temperature):
        self.calls.append((system, user, temperature))
        return self.responses.pop(0)


class SingleAgentTests(unittest.TestCase):
    def test_reflexion_revises_previous_c_until_target_passes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            model = QueueModel([
                "```c\nint main(void) { return 1; }\n```",
                "The return value changed; preserve the original observable result.",
                "```c\nint main(void) { return 0; }\n```",
            ])

            def evaluate(candidate):
                detected = "return 1" in candidate.read_text(encoding="utf-8")
                return (0.2 if detected else 0.8), feedback(detected)

            result = ReflexionRunner(
                model,
                evaluate,
                detector_success("ember"),
                ReflexionConfig(max_attempts=3),
            ).run(source, root / "output")

            self.assertTrue(result["success"])
            self.assertEqual(result["attempt_count"], 2)
            self.assertEqual(result["reflection_count"], 1)
            self.assertIn("return 0", (root / "output" / "best.c").read_text())
            self.assertIn("return 1", model.calls[2][1])
            self.assertIn("preserve the original", model.calls[2][1])
            self.assertEqual(len((root / "output" / "attempts.jsonl").read_text().splitlines()), 2)
            self.assertEqual(len((root / "output" / "reflections.jsonl").read_text().splitlines()), 1)

    def test_last_failed_attempt_is_kept_without_unused_reflection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            model = QueueModel(["int main(void) { return 1; }"])
            result = ReflexionRunner(
                model,
                lambda _candidate: (0.2, feedback(True)),
                detector_success("ember"),
                ReflexionConfig(max_attempts=1),
            ).run(source, root / "output")
            self.assertFalse(result["success"])
            self.assertEqual(result["reflection_count"], 0)
            self.assertTrue((root / "output" / "best.c").is_file())

    def test_code_block_extraction_and_build_failure(self):
        self.assertEqual(extract_c_code("```c\nint x;\n```"), "int x;\n")
        self.assertFalse(detector_success("ember")({"build": "BUILD_FAIL"}))


if __name__ == "__main__":
    unittest.main()
