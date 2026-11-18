from __future__ import annotations

import json
import math
import random
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from pipeline.ga_only.operators import Gene, TigressPool


@dataclass(frozen=True)
class RandomSearchConfig:
    query_budget: int = 32
    min_actions: int = 1
    max_actions: int = 2
    seed: int = 0
    stop_on_success: bool = True

    def __post_init__(self):
        integers = (self.query_budget, self.min_actions, self.max_actions)
        if any(isinstance(val, bool) or not isinstance(val, int) or val <= 0 for val in integers):
            raise ValueError("query_budget, min_actions, and max_actions must be positive integers")
        if self.min_actions > self.max_actions:
            raise ValueError("min_actions cannot exceed max_actions")


Evaluator = Callable[[Path], tuple[float, dict]]
SuccessPredicate = Callable[[dict], bool]


class RandomSearchRunner:
    def __init__(
        self,
        pool: TigressPool,
        evaluator: Evaluator,
        is_success: SuccessPredicate,
        target: str,
        config: RandomSearchConfig | None = None,
    ):
        self.pool = pool
        self.evaluator = evaluator
        self.is_success = is_success
        self.target = target
        self.config = config or RandomSearchConfig()
        self.random = random.Random(self.config.seed)
        self.evaluations = 0
        self.operator_names = sorted(self.pool.operators.keys())
        if not self.operator_names:
            raise ValueError("Operator pool has no operators")

    def _sample_genes(self) -> list[Gene]:
        length = self.random.randint(self.config.min_actions, self.config.max_actions)
        return [
            Gene(
                operator=self.random.choice(self.operator_names),
                seed=self.random.randrange(2**31),
            )
            for _ in range(length)
        ]

    def run(self, source: Path, output: Path) -> dict:
        source = Path(source).resolve()
        output = Path(output).resolve()
        if not source.is_file() or source.suffix.lower() != ".c":
            raise ValueError(f"Expected an existing .c source: {source}")
        if output.exists() and (not output.is_dir() or any(output.iterdir())):
            raise ValueError(f"Output directory must be an empty directory: {output}")
        output.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, output / "original.c")

        attempts_dir = output / "attempts"
        attempts_dir.mkdir(parents=True, exist_ok=True)

        best_fitness = float("-inf")
        best_source: Path | None = None
        best_genes: list[Gene] = []
        best_evaluation: dict = {}
        success = False
        ledger_path = output / "evaluations.jsonl"

        with ledger_path.open("w", encoding="utf-8") as ledger:
            while self.evaluations < self.config.query_budget:
                genes = self._sample_genes()
                candidate = attempts_dir / f"attempt-{self.evaluations:03d}.c"
                self.evaluations += 1
                try:
                    trace = self.pool.transform(source, tuple(genes), candidate)
                    fitness, details = self.evaluator(candidate)
                    if isinstance(fitness, bool) or not isinstance(fitness, (int, float)) or not math.isfinite(fitness):
                        raise ValueError("Evaluator fitness must be a finite number")
                    if not isinstance(details, dict):
                        raise ValueError("Evaluator details must be an object")
                    cand_success = self.is_success(details)
                    record = {
                        "evaluation": self.evaluations,
                        "candidate": str(candidate),
                        "genes": [asdict(g) for g in genes],
                        "fitness": float(fitness),
                        "success": cand_success,
                        "details": details,
                        "trace": trace,
                    }
                    ledger.write(json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n")
                    ledger.flush()
                except Exception as error:
                    record = {
                        "evaluation": self.evaluations,
                        "candidate": str(candidate),
                        "genes": [asdict(g) for g in genes],
                        "success": False,
                        "error": str(error),
                    }
                    ledger.write(json.dumps(record, ensure_ascii=False) + "\n")
                    ledger.flush()
                    continue

                if fitness > best_fitness:
                    best_fitness = float(fitness)
                    best_source = candidate
                    best_genes = list(genes)
                    best_evaluation = details

                if cand_success:
                    success = True
                    if self.config.stop_on_success:
                        break

        if best_source is None:
            raise RuntimeError("No candidate could be transformed and evaluated")

        shutil.copyfile(best_source, output / "best.c")
        result = {
            "input": str(source),
            "target": self.target,
            "success": success,
            "best_source": str(output / "best.c"),
            "best_fitness": best_fitness,
            "best_genes": [asdict(g) for g in best_genes],
            "best_evaluation": best_evaluation,
            "evaluations": self.evaluations,
            "config": asdict(self.config),
            "evaluations_file": str(ledger_path),
        }
        (output / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return result
