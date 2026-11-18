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
class XPriMESConfig:
    query_budget: int = 32
    max_actions: int = 6
    seed: int = 0
    replay_capacity: int = 64
    replay_batch_size: int = 4
    surrogate_engine: str = "ember"

    def __post_init__(self):
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value <= 0
            for value in (self.query_budget, self.max_actions, self.replay_capacity, self.replay_batch_size)
        ):
            raise ValueError("All integer configurations must be positive integers")


@dataclass
class Arm:
    name: str
    alpha: float = 1.0
    beta: float = 1.0
    pulls: int = 0
    rewards: float = 0.0


@dataclass
class ReplayItem:
    arm_name: str
    dense_reward: float
    success: bool
    shap_impact: float
    priority: float


Evaluator = Callable[[Path], tuple[float, dict]]
SuccessPredicate = Callable[[dict], bool]


class XPriMESRunner:
    def __init__(
        self,
        pool: TigressPool,
        evaluator: Evaluator,
        is_success: SuccessPredicate,
        target: str = "ember",
        config: XPriMESConfig | None = None,
    ):
        self.pool = pool
        self.evaluator = evaluator
        self.is_success = is_success
        self.target = target
        self.config = config or XPriMESConfig()
        self.random = random.Random(self.config.seed)
        self.arms = {name: Arm(name) for name in pool.operators}
        self.replay_buffer: list[ReplayItem] = []
        self.evaluations = 0

    def _select(self) -> tuple[Arm, float]:
        draws = [
            (self.random.betavariate(max(1e-3, arm.alpha), max(1e-3, arm.beta)), arm)
            for arm in self.arms.values()
        ]
        draw, arm = max(draws, key=lambda item: item[0])
        return arm, draw

    def _extract_surrogate_score(self, details: dict, default_fitness: float) -> float:
        surrogate = details.get("detectors", {}).get(self.config.surrogate_engine, {})
        if isinstance(surrogate, dict) and "score" in surrogate and isinstance(surrogate["score"], (int, float)):
            return float(surrogate["score"])
        return max(0.0, 1.0 - default_fitness)

    def _compute_shap_impact(self, details: dict, prev_score: float, curr_score: float) -> float:
        # Dual-environment SHAP guidance: magnitude of surrogate score drop
        score_drop = max(0.0, prev_score - curr_score)
        surrogate = details.get("detectors", {}).get(self.config.surrogate_engine, {})
        # If detector provides explicit feature attribution summary, incorporate it
        feat_contrib = surrogate.get("shap_contrib_norm", 0.0) if isinstance(surrogate, dict) else 0.0
        return float(score_drop * (1.0 + feat_contrib))

    def _add_replay(self, arm_name: str, dense_reward: float, success: bool, shap_impact: float):
        priority = max(1e-3, dense_reward + (1.0 if success else 0.0) + shap_impact)
        if len(self.replay_buffer) >= self.config.replay_capacity:
            self.replay_buffer.pop(0)
        self.replay_buffer.append(
            ReplayItem(
                arm_name=arm_name,
                dense_reward=dense_reward,
                success=success,
                shap_impact=shap_impact,
                priority=priority,
            )
        )

    def _replay_update(self):
        if not self.replay_buffer:
            return
        weights = [item.priority for item in self.replay_buffer]
        k = min(len(self.replay_buffer), self.config.replay_batch_size)
        batch = self.random.choices(self.replay_buffer, weights=weights, k=k)
        for item in batch:
            arm = self.arms[item.arm_name]
            if item.dense_reward > 0.0 or item.success:
                arm.alpha += max(0.1, item.dense_reward + (1.0 if item.success else 0.0))
            else:
                arm.beta += 0.5

    def _evaluate(
        self,
        original: Path,
        genes: list[Gene],
        candidate: Path,
        phase: str,
        selected: Arm | None,
        draw: float | None,
        ledger,
    ) -> tuple[float, dict, bool]:
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
            reduced = minimized[:index] + minimized[index + 1 :]
            candidate = directory / f"trial-{trial:03d}.c"
            trial += 1
            try:
                _, _, success = self._evaluate(original, reduced, candidate, "minimize", None, None, ledger)
            except Exception as error:
                ledger.write(
                    json.dumps(
                        {"evaluation": self.evaluations, "phase": "minimize", "candidate": str(candidate), "error": str(error)},
                        ensure_ascii=False,
                    )
                    + "\n"
                )
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

        # Initial baseline evaluation
        init_candidate = output / "initial.c"
        shutil.copyfile(source, init_candidate)
        ledger_path = output / "evaluations.jsonl"

        with ledger_path.open("w", encoding="utf-8") as ledger:
            init_fitness, init_details, init_success = self._evaluate(
                source, [], init_candidate, "baseline", None, None, ledger
            )
            prev_surrogate = self._extract_surrogate_score(init_details, init_fitness)

            genes: list[Gene] = []
            episode = 0
            best_fitness = init_fitness
            best_source = init_candidate
            best_genes: list[Gene] = []
            successful_genes = [] if init_success else None

            if not init_success:
                while self.evaluations < self.config.query_budget:
                    if len(genes) >= self.config.max_actions:
                        genes = []
                        episode += 1
                        prev_surrogate = self._extract_surrogate_score(init_details, init_fitness)

                    arm, draw = self._select()
                    arm.pulls += 1
                    genes.append(Gene(arm.name, self.random.randrange(2**31)))
                    candidate = output / "attempts" / f"attempt-{self.evaluations:03d}.c"

                    try:
                        fitness, details, success = self._evaluate(
                            source, genes, candidate, "search", arm, draw, ledger
                        )
                    except Exception as error:
                        arm.beta += 1.0
                        ledger.write(
                            json.dumps(
                                {
                                    "evaluation": self.evaluations,
                                    "phase": "search",
                                    "candidate": str(candidate),
                                    "selected_arm": arm.name,
                                    "posterior_draw": draw,
                                    "genes": [asdict(gene) for gene in genes],
                                    "success": False,
                                    "error": str(error),
                                },
                                ensure_ascii=False,
                            )
                            + "\n"
                        )
                        ledger.flush()
                        genes = []
                        episode += 1
                        prev_surrogate = self._extract_surrogate_score(init_details, init_fitness)
                        continue

                    # Dual-environment reward shaping
                    curr_surrogate = self._extract_surrogate_score(details, fitness)
                    dense_reward = max(0.0, prev_surrogate - curr_surrogate)
                    shap_impact = self._compute_shap_impact(details, prev_surrogate, curr_surrogate)

                    # Update arm immediate feedback
                    if dense_reward > 0.0:
                        arm.alpha += dense_reward
                        arm.rewards += dense_reward
                    else:
                        arm.beta += 0.5

                    # Add experience to prioritized replay
                    self._add_replay(arm.name, dense_reward, success, shap_impact)
                    self._replay_update()
                    prev_surrogate = curr_surrogate

                    if fitness > best_fitness:
                        best_fitness = fitness
                        best_source = candidate
                        best_genes = list(genes)

                    if success:
                        successful_genes = self._minimize(source, genes, output, ledger)
                        for gene in successful_genes:
                            rewarded = self.arms[gene.operator]
                            rewarded.alpha += 2.0
                            rewarded.rewards += 2.0
                        minimized = output / "minimized.c"
                        self.pool.transform(source, tuple(successful_genes), minimized)
                        break

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
            "replay_buffer_size": len(self.replay_buffer),
            "config": asdict(self.config),
            "evaluations_file": str(ledger_path),
        }
        (output / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return result
