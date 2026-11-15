from __future__ import annotations

import json
import math
import re
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable


ACTOR_SYSTEM = """You are a C programming assistant in a defensive detector benchmark.
Rewrite the complete C program while preserving its externally observable behavior.
Do not add capabilities or remove intended behavior. Return only one complete C program
inside a ```c code block, with no explanation outside the block."""

REFLECTION_SYSTEM = """You are a C programming assistant using Reflexion.
Given a failed implementation and grounded evaluator feedback, explain in a few sentences
why the attempt failed and what structural change should be tried next. Return only the
reflection, not code."""


@dataclass(frozen=True)
class ReflexionConfig:
    max_attempts: int = 5
    target: str = "ember"

    def __post_init__(self):
        if isinstance(self.max_attempts, bool) or not isinstance(self.max_attempts, int) or self.max_attempts <= 0:
            raise ValueError("max_attempts must be a positive integer")
        if not isinstance(self.target, str) or not self.target:
            raise ValueError("target must be a non-empty string")


Generate = Callable[[str, str, float], str]
Evaluator = Callable[[Path], tuple[float, dict]]
SuccessPredicate = Callable[[dict], bool]


def extract_c_code(response: str) -> str:
    if not isinstance(response, str) or not response.strip():
        raise ValueError("Actor returned an empty response")
    blocks = re.findall(r"```(?:c|C)?\s*\n(.*?)```", response, flags=re.DOTALL)
    code = blocks[0].strip() if blocks else response.strip()
    if not code:
        raise ValueError("Actor returned an empty C program")
    return code + "\n"


class ReflexionRunner:
    def __init__(
        self,
        generate: Generate,
        evaluator: Evaluator,
        is_success: SuccessPredicate,
        config: ReflexionConfig | None = None,
    ):
        self.generate = generate
        self.evaluator = evaluator
        self.is_success = is_success
        self.config = config or ReflexionConfig()

    @staticmethod
    def _initial_prompt(source: str) -> str:
        return f"""Create the first structurally different implementation of this program.

[original C program]
```c
{source.rstrip()}
```
"""

    @staticmethod
    def _revision_prompt(previous: str, feedback: dict, reflection: str) -> str:
        return f"""Improve the previous implementation using the evaluator feedback and self-reflection.

[previous C implementation]
```c
{previous.rstrip()}
```

[evaluator feedback]
{json.dumps(feedback, indent=2, ensure_ascii=False)}

[self-reflection]
{reflection.strip()}
"""

    @staticmethod
    def _reflection_prompt(candidate: str, feedback: dict) -> str:
        return f"""Analyze this failed attempt.

[C implementation]
```c
{candidate.rstrip()}
```

[evaluator feedback]
{json.dumps(feedback, indent=2, ensure_ascii=False)}
"""

    def run(self, source: Path, output: Path) -> dict:
        source = Path(source).resolve()
        output = Path(output).resolve()
        if not source.is_file() or source.suffix.lower() != ".c":
            raise ValueError(f"Expected an existing .c source: {source}")
        if output.exists() and (not output.is_dir() or any(output.iterdir())):
            raise ValueError(f"Output directory must be an empty directory: {output}")

        output.mkdir(parents=True, exist_ok=True)
        attempts_dir = output / "attempts"
        attempts_dir.mkdir()
        shutil.copyfile(source, output / "original.c")

        original = source.read_text(encoding="utf-8")
        previous = original
        previous_feedback: dict | None = None
        reflection: str | None = None
        best_fitness = float("-inf")
        best_source: Path | None = None
        success = False
        attempts = []
        reflections = []

        attempts_path = output / "attempts.jsonl"
        reflections_path = output / "reflections.jsonl"
        with attempts_path.open("w", encoding="utf-8") as attempt_log, reflections_path.open("w", encoding="utf-8") as reflection_log:
            for number in range(1, self.config.max_attempts + 1):
                prompt = self._initial_prompt(original) if number == 1 else self._revision_prompt(previous, previous_feedback or {}, reflection or "")
                candidate = extract_c_code(self.generate(ACTOR_SYSTEM, prompt, 0.2))
                candidate_path = attempts_dir / f"attempt-{number:03d}.c"
                candidate_path.write_text(candidate, encoding="utf-8")

                fitness, feedback = self.evaluator(candidate_path)
                if isinstance(fitness, bool) or not isinstance(fitness, (int, float)) or not math.isfinite(fitness):
                    raise ValueError("Evaluator fitness must be a finite number")
                if not isinstance(feedback, dict):
                    raise ValueError("Evaluator feedback must be an object")

                success = bool(self.is_success(feedback))
                record = {
                    "attempt": number,
                    "source": str(candidate_path),
                    "fitness": float(fitness),
                    "success": success,
                    "feedback": feedback,
                }
                attempts.append(record)
                attempt_log.write(json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n")
                attempt_log.flush()

                if success or fitness > best_fitness:
                    best_fitness = float(fitness)
                    best_source = candidate_path
                if success or number == self.config.max_attempts:
                    break

                reflection = self.generate(REFLECTION_SYSTEM, self._reflection_prompt(candidate, feedback), 0.0).strip()
                if not reflection:
                    raise ValueError("Self-Reflector returned an empty response")
                reflection_record = {"after_attempt": number, "reflection": reflection}
                reflections.append(reflection_record)
                reflection_log.write(json.dumps(reflection_record, ensure_ascii=False) + "\n")
                reflection_log.flush()
                previous = candidate
                previous_feedback = feedback

        if best_source is None:
            raise RuntimeError("No candidate could be generated and evaluated")
        shutil.copyfile(best_source, output / "best.c")
        result = {
            "input": str(source),
            "success": success,
            "target": self.config.target,
            "best_source": str(output / "best.c"),
            "best_fitness": best_fitness,
            "attempt_count": len(attempts),
            "reflection_count": len(reflections),
            "attempts_file": str(attempts_path),
            "reflections_file": str(reflections_path),
            "config": asdict(self.config),
        }
        (output / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return result
