from __future__ import annotations

import json
import math
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from pipeline.ga_only.operators import Gene, TigressPool


@dataclass(frozen=True)
class Recipe:
    name: str
    steps: tuple[Gene, ...]

    @classmethod
    def load(cls, path: Path) -> "Recipe":
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(document, dict) or set(document) != {"name", "steps"}:
            raise ValueError("Recipe must contain only name and steps")
        if not isinstance(document["name"], str) or not document["name"]:
            raise ValueError("Recipe name must be a non-empty string")
        raw_steps = document["steps"]
        if not isinstance(raw_steps, list) or not raw_steps:
            raise ValueError("Recipe steps must be a non-empty list")
        steps = []
        for item in raw_steps:
            if not isinstance(item, dict) or set(item) != {"operator", "seed"}:
                raise ValueError("Each recipe step must contain operator and seed")
            operator, seed = item["operator"], item["seed"]
            if not isinstance(operator, str) or not operator or operator == "noop":
                raise ValueError("Recipe operators must be non-empty and not noop")
            if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed < 2**31:
                raise ValueError("Recipe seeds must be integers within [0, 2^31)")
            steps.append(Gene(operator, seed))
        return cls(document["name"], tuple(steps))


Evaluator = Callable[[Path], tuple[float, dict]]


class HeuristicRunner:
    def __init__(self, pool: TigressPool, evaluator: Evaluator):
        self.pool = pool
        self.evaluator = evaluator

    def run(self, source: Path, recipe: Recipe, output: Path) -> dict:
        source = Path(source).resolve()
        output = Path(output).resolve()
        if not source.is_file() or source.suffix.lower() != ".c":
            raise ValueError(f"Expected an existing .c source: {source}")
        unknown = {step.operator for step in recipe.steps} - set(self.pool.operators)
        if unknown:
            raise ValueError("Unknown recipe operators: " + ", ".join(sorted(unknown)))
        if output.exists() and (not output.is_dir() or any(output.iterdir())):
            raise ValueError(f"Output directory must be an empty directory: {output}")
        output.mkdir(parents=True, exist_ok=True)
        original = output / "original.c"
        shutil.copyfile(source, original)

        current = source
        stages = []
        for index, step in enumerate(recipe.steps, 1):
            destination = output / "stages" / f"stage-{index:03d}-{step.operator}.c"
            input_bytes = current.stat().st_size
            trace = self.pool.transform(current, (step,), destination)
            stages.append({
                "index": index,
                **asdict(step),
                "input": str(current),
                "output": str(destination),
                "input_bytes": input_bytes,
                "output_bytes": destination.stat().st_size,
                "trace": trace,
            })
            current = destination

        final_source = output / "final.c"
        shutil.copyfile(current, final_source)
        fitness, evaluation = self.evaluator(final_source)
        if isinstance(fitness, bool) or not isinstance(fitness, (int, float)) or not math.isfinite(fitness):
            raise ValueError("Evaluator fitness must be a finite number")
        if not isinstance(evaluation, dict):
            raise ValueError("Evaluator details must be an object")
        original_bytes = original.stat().st_size
        final_bytes = final_source.stat().st_size
        result = {
            "input": str(source),
            "recipe": recipe.name,
            "steps": stages,
            "final_source": str(final_source),
            "fitness": float(fitness),
            "evaluation": evaluation,
            "original_bytes": original_bytes,
            "final_bytes": final_bytes,
            "growth_ratio": final_bytes / original_bytes,
        }
        (output / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return result

