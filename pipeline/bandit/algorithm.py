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
class BanditConfig:
    query_budget: int = 32
    max_actions: int = 6
    seed: int = 0

    def __post_init__(self):
        if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in (self.query_budget, self.max_actions)):
            raise ValueError("Bandit query_budget and max_actions must be positive integers")


@dataclass
class Arm:
    name: str
    alpha: int = 1
    beta: int = 1
    pulls: int = 0
    rewards: int = 0


Evaluator = Callable[[Path], tuple[float, dict]]
SuccessPredicate = Callable[[dict], bool]


class BanditRunner:
    def __init__(self, pool: TigressPool, evaluator: Evaluator, is_success: SuccessPredicate, target: str, config: BanditConfig | None = None):
        self.pool = pool
        self.evaluator = evaluator
        self.is_success = is_success
        self.target = target
        self.config = config or BanditConfig()
        self.random = random.Random(self.config.seed)
        self.arms = {name: Arm(name) for name in pool.operators}
        self.evaluations = 0

    def _select(self) -> tuple[Arm, float]:
        draws = [(self.random.betavariate(arm.alpha, arm.beta), arm) for arm in self.arms.values()]
        draw, arm = max(draws, key=lambda item: item[0])
        return arm, draw

    def _evaluate(self, original: Path, genes: list[Gene], candidate: Path, phase: str, selected: Arm | None, draw: float | None, ledger) -> tuple[float, dict, bool]:
        self.evaluations += 1
        trace = self.pool.transform(original, tuple(genes), candidate)
        fitness, details = self.evaluator(candidate)
        if isinstance(fitness, bool) or not isinstance(fitness, (int, float)) or not math.isfinite(fitness):
            raise ValueError("Evaluator fitness must be a finite number")
        if not isinstance(details, dict):
            raise ValueError("Evaluator details must be an object")
        success = bool(self.is_success(details))
        record = {
            "evaluation": self.evaluations,
            "phase": phase,
            "candidate": str(candidate),
            "selected_arm": selected.name if selected else None,
            "posterior_draw": draw,
            "genes": [asdict(gene) for gene in genes],
            "fitness": float(fitness),
            "success": success,
            "details": details,
            "trace": trace,
        }
        ledger.write(json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n")
        ledger.flush()
        return float(fitness), details, success

    def _minimize(self, original: Path, genes: list[Gene], root: Path, ledger) -> list[Gene]:
        minimized = list(genes)
        index = 0
        trial = 0
        directory = root / "minimization"
        while index < len(minimized) and self.evaluations < self.config.query_budget:
            reduced = minimized[:index] + minimized[index + 1:]
            candidate = directory / f"trial-{trial:03d}.c"
            trial += 1
            try:
                _, _, success = self._evaluate(original, reduced, candidate, "minimize", None, None, ledger)
            except Exception as error:
                ledger.write(json.dumps({"evaluation": self.evaluations, "phase": "minimize", "candidate": str(candidate), "error": str(error)}, ensure_ascii=False) + "\n")
                ledger.flush()
                success = False
            if success:
                minimized = reduced
            else:
                index += 1
        return minimized

    def run(self, source: Path, output: Path) -> dict:
        source = Path(source).resolve()
        output = Path(output).resolve()
        if not source.is_file() or source.suffix.lower() != ".c":
            raise ValueError(f"Expected an existing .c source: {source}")
        if output.exists() and (not output.is_dir() or any(output.iterdir())):
            raise ValueError(f"Output directory must be an empty directory: {output}")
        output.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, output / "original.c")

        genes: list[Gene] = []
        episode = 0
        best_fitness = float("-inf")
        best_source = None
        best_genes: list[Gene] = []
        successful_genes = None
        ledger_path = output / "evaluations.jsonl"
        with ledger_path.open("w", encoding="utf-8") as ledger:
            while self.evaluations < self.config.query_budget:
                if len(genes) >= self.config.max_actions:
                    genes = []
                    episode += 1
                arm, draw = self._select()
                arm.pulls += 1
                genes.append(Gene(arm.name, self.random.randrange(2**31)))
                candidate = output / "attempts" / f"attempt-{self.evaluations:03d}.c"
                try:
                    fitness, _, success = self._evaluate(source, genes, candidate, "search", arm, draw, ledger)
                except Exception as error:
                    arm.beta += 1
                    ledger.write(json.dumps({"evaluation": self.evaluations, "phase": "search", "candidate": str(candidate), "selected_arm": arm.name, "posterior_draw": draw, "genes": [asdict(gene) for gene in genes], "success": False, "error": str(error)}, ensure_ascii=False) + "\n")
                    ledger.flush()
                    genes = []
                    episode += 1
                    continue
                if fitness > best_fitness:
                    best_fitness = fitness
                    best_source = candidate
                    best_genes = list(genes)
                if success:
                    successful_genes = self._minimize(source, genes, output, ledger)
                    for gene in successful_genes:
                        rewarded = self.arms[gene.operator]
                        rewarded.alpha += 1
                        rewarded.rewards += 1
                    minimized = output / "minimized.c"
                    self.pool.transform(source, tuple(successful_genes), minimized)
                    break
                arm.beta += 1

        if best_source is None:
            raise RuntimeError("No candidate could be transformed and evaluated")
        shutil.copyfile(best_source, output / "best.c")
        result = {
            "input": str(source),
            "target": self.target,
            "success": successful_genes is not None,
            "best_source": str(output / "best.c"),
            "best_fitness": best_fitness,
            "best_genes": [asdict(gene) for gene in best_genes],
            "minimized_source": str(output / "minimized.c") if successful_genes is not None else None,
            "minimized_genes": [asdict(gene) for gene in successful_genes] if successful_genes is not None else None,
            "evaluations": self.evaluations,
            "episodes": episode + 1,
            "arms": {name: asdict(arm) for name, arm in sorted(self.arms.items())},
            "config": asdict(self.config),
            "evaluations_file": str(ledger_path),
        }
        (output / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return result

