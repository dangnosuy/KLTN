from __future__ import annotations

import hashlib
import json
import math
import random
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from pipeline.ga_only.operators import Gene, TigressPool
from pipeline.single_agent.algorithm import extract_c_code

PROPOSED_LLM_SYSTEM = """You are the Semantic Reflexion Agent in an adaptive hybrid optimization framework (Proposed C2 + NSGA-II).
Your goal is to inspect the current Pareto-optimal solutions, diagnostic evaluator feedback, and stagnation signals, then formulate an innovative code normalization recipe or directly synthesize a refactored C candidate that normalizes binary structural representation.

Effective normalization strategies:
1. Dynamic API Resolution: resolve Win32 APIs (VirtualAlloc, CreateFileMappingA, MapViewOfFile, CreateThread, WaitForSingleObject) via GetProcAddress/LoadLibraryA to eliminate suspicious static import table (IAT) entries.
2. Auxiliary Workload: insert realistic computational helpers (matrix multiplication, CRC32/checksum calculation, string formatting) invoked from main to normalize PE feature distributions.
3. String Storage: construct API name strings on stack or decode them immediately before use.

You can return EITHER:
Option A (Semantic C Code Rewrite - RECOMMENDED when stagnant):
Return a complete, self-contained, working C program inside a ```c code block that implements dynamic API resolution and auxiliary workload dilution while strictly preserving execution semantics.

Option B (Operator Sequence Recipe):
Return exactly one JSON object with keys "thought" and "genes" using only the available operators:
{"thought": "...", "genes": [{"operator": "...", "seed": 42}, ...]}"""


@dataclass(frozen=True)
class ProposedConfig:
    population_size: int = 8
    generations: int = 5
    chromosome_length: int = 4
    tournament_size: int = 3
    crossover_rate: float = 0.70
    mutation_rate: float = 0.20
    noop_rate: float = 0.25
    stagnation_patience: int = 2
    failure_rate_threshold: float = 0.50
    max_llm_calls: int = 6
    max_evaluations: int = 48
    seed: int = 0

    def __post_init__(self):
        integers = (
            self.population_size,
            self.generations,
            self.chromosome_length,
            self.tournament_size,
            self.stagnation_patience,
            self.max_llm_calls,
            self.max_evaluations,
        )
        if any(isinstance(val, bool) or not isinstance(val, int) or val <= 0 for val in integers):
            raise ValueError("All integer configurations must be positive integers")
        if self.tournament_size > self.population_size:
            raise ValueError("tournament_size cannot exceed population_size")
        for rate_name in ("crossover_rate", "mutation_rate", "noop_rate", "failure_rate_threshold"):
            val = getattr(self, rate_name)
            if not isinstance(val, (int, float)) or not 0 <= val <= 1:
                raise ValueError(f"{rate_name} must be within [0, 1]")


@dataclass(eq=False)
class ProposedIndividual:
    genes: tuple[Gene, ...] = ()
    thought: str = "Standard EA individual"
    origin: str = "ea"
    fitness: float = 0.0
    objectives: tuple[float, float] = (0.0, 0.0)  # (evasion_fitness, compactness_ratio)
    rank: int = 0
    crowding_distance: float = 0.0
    source: str | None = None
    evaluation: dict | None = None
    custom_code: str | None = None

    @property
    def key(self):
        if self.custom_code:
            return ("custom_code", hashlib.sha256(self.custom_code.encode("utf-8")).hexdigest())
        return tuple((gene.operator, gene.seed) for gene in self.genes)


Generate = Callable[[str, str, float], str]
Evaluator = Callable[[Path], tuple[float, dict]]


# ---------------------------------------------------------------------------
# NSGA-II Core Algorithms
# ---------------------------------------------------------------------------

def dominates(ind1: ProposedIndividual, ind2: ProposedIndividual) -> bool:
    """True if ind1 Pareto-dominates ind2 (both objectives are maximized)."""
    o1, o2 = ind1.objectives, ind2.objectives
    greater_or_equal = (o1[0] >= o2[0]) and (o1[1] >= o2[1])
    strictly_better = (o1[0] > o2[0]) or (o1[1] > o2[1])
    return greater_or_equal and strictly_better


def fast_non_dominated_sort(population: list[ProposedIndividual]) -> list[list[ProposedIndividual]]:
    """Fast Non-Dominated Sorting algorithm from Deb et al. (NSGA-II)."""
    dominated_solutions: dict[int, list[int]] = {i: [] for i in range(len(population))}
    domination_counts: list[int] = [0] * len(population)
    fronts: list[list[int]] = [[]]

    for p in range(len(population)):
        for q in range(len(population)):
            if dominates(population[p], population[q]):
                dominated_solutions[p].append(q)
            elif dominates(population[q], population[p]):
                domination_counts[p] += 1
        if domination_counts[p] == 0:
            population[p].rank = 1
            fronts[0].append(p)

    current_front_idx = 0
    while current_front_idx < len(fronts) and fronts[current_front_idx]:
        next_front: list[int] = []
        for p in fronts[current_front_idx]:
            for q in dominated_solutions[p]:
                domination_counts[q] -= 1
                if domination_counts[q] == 0:
                    population[q].rank = current_front_idx + 2
                    next_front.append(q)
        current_front_idx += 1
        if next_front:
            fronts.append(next_front)

    return [[population[idx] for idx in front] for front in fronts if front]


def assign_crowding_distance(front: list[ProposedIndividual]) -> None:
    """Assign crowding distance to a single Pareto front."""
    size = len(front)
    if size == 0:
        return
    for ind in front:
        ind.crowding_distance = 0.0

    if size <= 2:
        for ind in front:
            ind.crowding_distance = float("inf")
        return

    num_objectives = len(front[0].objectives)
    for m in range(num_objectives):
        front.sort(key=lambda ind: ind.objectives[m])
        front[0].crowding_distance = float("inf")
        front[-1].crowding_distance = float("inf")
        obj_range = front[-1].objectives[m] - front[0].objectives[m]
        if obj_range > 1e-9:
            for i in range(1, size - 1):
                front[i].crowding_distance += (front[i + 1].objectives[m] - front[i - 1].objectives[m]) / obj_range


def crowded_comparison(ind1: ProposedIndividual, ind2: ProposedIndividual) -> bool:
    """True if ind1 is strictly preferred over ind2 in NSGA-II."""
    if ind1.rank < ind2.rank:
        return True
    if ind1.rank == ind2.rank:
        return ind1.crowding_distance > ind2.crowding_distance
    return False


def environmental_selection(
    combined: list[ProposedIndividual], target_size: int
) -> list[ProposedIndividual]:
    """Select the best target_size individuals from combined population."""
    fronts = fast_non_dominated_sort(combined)
    survivors: list[ProposedIndividual] = []

    for front in fronts:
        assign_crowding_distance(front)
        if len(survivors) + len(front) <= target_size:
            survivors.extend(front)
        else:
            needed = target_size - len(survivors)
            front.sort(key=lambda ind: ind.crowding_distance, reverse=True)
            survivors.extend(front[:needed])
            break

    return survivors


def calculate_2d_hypervolume(front: list[ProposedIndividual]) -> float:
    """Compute exact 2D hypervolume for non-dominated front against reference point (0, 0)."""
    if not front:
        return 0.0
    # Collect non-zero points and sort by obj[0] ascending
    pts = [(ind.objectives[0], ind.objectives[1]) for ind in front if ind.objectives[0] > 0 and ind.objectives[1] > 0]
    if not pts:
        return 0.0
    pts = sorted(set(pts), key=lambda p: p[0])

    hv = 0.0
    prev_x = 0.0
    for i in range(len(pts)):
        curr_x, curr_y = pts[i]
        width = curr_x - prev_x
        # Height is max y from i to end
        max_y = max(p[1] for p in pts[i:])
        hv += width * max_y
        prev_x = curr_x
    return hv


# ---------------------------------------------------------------------------
# Proposed Runner (C2 Coordinator + NSGA-II + Reflexion)
# ---------------------------------------------------------------------------

def parse_llm_genes(response: str, operators: set[str], chromosome_length: int) -> tuple[str, tuple[Gene, ...]]:
    start = response.find("{")
    if start < 0:
        raise ValueError("LLM response contains no JSON object")
    document, _ = json.JSONDecoder().raw_decode(response[start:])
    if not isinstance(document, dict) or not {"thought", "genes"}.issubset(document.keys()):
        raise ValueError("LLM JSON must contain thought and genes")
    thought = document["thought"]
    raw_genes = document["genes"]
    if not isinstance(thought, str) or not thought.strip():
        raise ValueError("thought must be non-empty string")
    if not isinstance(raw_genes, list):
        raise ValueError("genes must be a list")

    genes = []
    for item in raw_genes[:chromosome_length]:
        if isinstance(item, str):
            op = item.strip().lower()
            if op in operators or op == "noop":
                genes.append(Gene(op, 42))
            continue
        if not isinstance(item, dict):
            continue
        op = item.get("operator") or item.get("name")
        if not op or (op not in operators and op != "noop"):
            continue
        seed = item.get("seed", 42)
        if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed < 2**31:
            try:
                seed = int(seed) % (2**31)
            except Exception:
                seed = 42
        genes.append(Gene(op, seed))

    while len(genes) < chromosome_length:
        genes.append(Gene("noop", 0))

    return thought.strip(), tuple(genes)


class ProposedRunner:
    def __init__(
        self,
        pool: TigressPool,
        evaluator: Evaluator,
        generate: Generate | None = None,
        config: ProposedConfig | None = None,
    ):
        self.pool = pool
        self.evaluator = evaluator
        self.generate = generate
        self.config = config or ProposedConfig()
        self.random = random.Random(self.config.seed)
        self.evaluations = 0
        self.llm_calls = 0
        self.stagnation_counter = 0
        self.last_hypervolume = 0.0
        self.c2_decisions: list[dict] = []
        self._source_cache: dict[str, tuple[float, dict]] = {}

    def _sample_gene(self) -> Gene:
        if self.random.random() < self.config.noop_rate:
            return Gene("noop", 0)
        return Gene(self.random.choice(sorted(self.pool.operators)), self.random.randrange(2**31))

    def _random_individual(self, origin: str = "initial") -> ProposedIndividual:
        genes = tuple(self._sample_gene() for _ in range(self.config.chromosome_length))
        return ProposedIndividual(genes=genes, origin=origin)

    def _tournament(self, population: list[ProposedIndividual]) -> ProposedIndividual:
        sample = self.random.sample(population, self.config.tournament_size)
        best = sample[0]
        for ind in sample[1:]:
            if crowded_comparison(ind, best):
                best = ind
        return best

    def _crossover(
        self, parent1: ProposedIndividual, parent2: ProposedIndividual
    ) -> tuple[ProposedIndividual, ProposedIndividual]:
        if parent1.custom_code or parent2.custom_code:
            # Custom code individual transfers directly or pairs with genes
            return (
                ProposedIndividual(parent1.genes, custom_code=parent1.custom_code, thought=parent1.thought),
                ProposedIndividual(parent2.genes, custom_code=parent2.custom_code, thought=parent2.thought),
            )
        if self.random.random() >= self.config.crossover_rate:
            return ProposedIndividual(parent1.genes), ProposedIndividual(parent2.genes)
        first, second = [], []
        for g1, g2 in zip(parent1.genes, parent2.genes):
            if self.random.random() < 0.5:
                first.append(g1)
                second.append(g2)
            else:
                first.append(g2)
                second.append(g1)
        return ProposedIndividual(tuple(first)), ProposedIndividual(tuple(second))

    def _mutate(self, individual: ProposedIndividual) -> ProposedIndividual:
        if individual.custom_code:
            return individual
        if self.random.random() >= self.config.mutation_rate:
            return individual
        genes = list(individual.genes)
        genes[self.random.randrange(len(genes))] = self._sample_gene()
        return ProposedIndividual(tuple(genes))

    def _evaluate_individual(
        self, ind: ProposedIndividual, original: Path, candidate: Path
    ) -> ProposedIndividual:
        if ind.custom_code:
            candidate.parent.mkdir(parents=True, exist_ok=True)
            candidate.write_text(ind.custom_code, encoding="utf-8")
            # If candidate uses local includes (e.g. "../common/payload_xor.h"), copy sibling directory structure
            for item in original.parent.iterdir():
                if item.name == original.name or item.name == "candidates":
                    continue
                target = candidate.parent / item.name
                if item.is_dir() and not target.exists():
                    shutil.copytree(item, target, dirs_exist_ok=True, ignore=shutil.ignore_patterns("candidates", "output"))
                elif item.is_file() and not target.exists():
                    shutil.copyfile(item, target)
            if "../" in ind.custom_code:
                parent_dir = original.parent.parent
                for item in parent_dir.iterdir():
                    if item.name == original.parent.name or item.name == "candidates" or item.name == "output":
                        continue
                    target = candidate.parent.parent / item.name
                    if item.is_dir() and not target.exists():
                        shutil.copytree(item, target, dirs_exist_ok=True, ignore=shutil.ignore_patterns("candidates", "output"))
                    elif item.is_file() and not target.exists():
                        shutil.copyfile(item, target)
            trace = [{"operator": "semantic_c_rewrite", "seed": 0}]
        else:
            trace = self.pool.transform(original, ind.genes, candidate)
        digest = hashlib.sha256(candidate.read_bytes()).hexdigest()

        if digest in self._source_cache:
            fitness, details = self._source_cache[digest]
            details = {**details, "cached": True}
        else:
            if self.evaluations >= self.config.max_evaluations:
                raise StopIteration
            fitness, details = self.evaluator(candidate)
            if isinstance(fitness, bool) or not isinstance(fitness, (int, float)) or not math.isfinite(fitness):
                raise ValueError("Evaluator fitness must be a finite number")
            if not isinstance(details, dict):
                raise ValueError("Evaluator details must be an object")
            self.evaluations += 1
            self._source_cache[digest] = (float(fitness), details)

        ind.fitness = float(fitness)
        ind.source = str(candidate)

        # Objective 1: Evasion fitness (normalized [0, 1])
        f1 = float(fitness)
        # Objective 2: Compactness / Anti-bloat ratio (original_size / candidate_size, clamped in (0, 1])
        orig_sz = original.stat().st_size
        cand_sz = candidate.stat().st_size
        f2 = min(1.0, orig_sz / max(1, cand_sz))

        # Failed builds receive 0 on both objectives (dominated)
        if details.get("build") != "PASSED":
            f1, f2 = 0.0, 0.0

        ind.objectives = (f1, f2)
        ind.evaluation = {**details, "source_sha256": digest, "trace": trace, "compactness": f2}
        return ind

    def _call_c2_reflexion(
        self, source_text: str, trigger_type: str, pareto_front: list[ProposedIndividual], failures: list[ProposedIndividual]
    ) -> ProposedIndividual:
        if not self.generate:
            return self._random_individual(origin="c2_fallback")

        self.llm_calls += 1
        pareto_summary = [
            {
                "thought": ind.thought,
                "genes": [asdict(g) for g in ind.genes],
                "objectives": {"fitness": ind.objectives[0], "compactness": ind.objectives[1]},
            }
            for ind in pareto_front[:4]
        ]
        failure_summary = [
            {
                "genes": [asdict(g) for g in ind.genes],
                "error": ind.evaluation.get("compiler_stderr", "") if ind.evaluation else "",
            }
            for ind in failures[:2]
        ]

        prompt = f"""C2 Coordinator Trigger: {trigger_type}
The evolutionary search has stalled at a local optimum. The baseline obfuscation operators alone cannot normalize static IAT imports or balance feature density.

You must optimize the C program representation to achieve binary structural normalization while strictly preserving execution behavior.

[Instructions]
1. Rewrite the C program to completely eliminate suspicious static imports (e.g. VirtualAlloc, CreateThread, WaitForSingleObject) using dynamic API resolution via GetProcAddress/LoadLibraryA.
2. Insert a realistic auxiliary workload function (matrix computation, or CRC32/checksum on a local dummy buffer, never referencing undeclared variables) invoked from main to normalize PE feature distributions and lower classifier anomaly score.
3. Obfuscate literal API name strings (e.g. stack strings or local byte-wise decoding).
4. Strictly preserve the original payload byte sequence, headers, and execution semantics.
5. Return your complete C program inside a single ```c code block.

[Current Pareto Front Solutions]
{json.dumps(pareto_summary, indent=2, ensure_ascii=False)}

[Recent Diagnostic Failures]
{json.dumps(failure_summary, indent=2, ensure_ascii=False)}

[Original Program]
```c
{source_text[:1500]}
```
"""
        try:
            response = self.generate(PROPOSED_LLM_SYSTEM, prompt, 0.2)
            # Check if LLM returned direct C code block (Option A)
            if "```c" in response:
                custom_code = extract_c_code(response)
                return ProposedIndividual(
                    genes=(),
                    thought=f"C2 Reflexion synthesized custom evasive C code ({trigger_type})",
                    origin=f"llm_{trigger_type.lower()}_code",
                    custom_code=custom_code,
                )
            # Otherwise parse operator recipe (Option B)
            thought, genes = parse_llm_genes(response, set(self.pool.operators), self.config.chromosome_length)
            return ProposedIndividual(genes=genes, thought=thought, origin=f"llm_{trigger_type.lower()}")
        except Exception as err:
            return ProposedIndividual(
                genes=self._random_individual().genes,
                thought=f"Fallback due to LLM error: {err}",
                origin="c2_fallback",
            )

    def run(self, source: Path, output: Path) -> dict:
        source = Path(source).resolve()
        output = Path(output).resolve()
        if not source.is_file() or source.suffix.lower() != ".c":
            raise ValueError(f"Expected an existing .c source: {source}")
        if output.exists() and (not output.is_dir() or any(output.iterdir())):
            raise ValueError(f"Output directory must be an empty directory: {output}")
        output.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, output / "original.c")

        source_text = source.read_text(encoding="utf-8", errors="replace")
        evaluations_log = output / "evaluations.jsonl"
        c2_log = output / "c2_decisions.jsonl"
        history = []

        with evaluations_log.open("w", encoding="utf-8") as f_eval, \
             c2_log.open("w", encoding="utf-8") as f_c2:

            # 1. Initialize Population
            population = [self._random_individual(origin="initial") for _ in range(self.config.population_size)]

            # Evaluate Generation 0
            gen_dir = output / "candidates" / "generation-000"
            gen_dir.mkdir(parents=True, exist_ok=True)
            for idx, ind in enumerate(population):
                cand = gen_dir / f"candidate-{idx:03d}.c"
                try:
                    self._evaluate_individual(ind, source, cand)
                except StopIteration:
                    break
                except Exception as err:
                    ind.objectives = (0.0, 0.0)
                    ind.fitness = 0.0
                    ind.evaluation = {"build": "BUILD_FAIL", "error": str(err)}
                rec = {
                    "generation": 0,
                    "candidate": idx,
                    "origin": ind.origin,
                    "thought": ind.thought,
                    "genes": [asdict(g) for g in ind.genes],
                    "fitness": ind.fitness,
                    "objectives": ind.objectives,
                    "evaluation": ind.evaluation,
                }
                f_eval.write(json.dumps(rec, ensure_ascii=False) + "\n")
                f_eval.flush()

            fronts = fast_non_dominated_sort(population)
            p1 = fronts[0] if fronts else []
            assign_crowding_distance(p1)
            self.last_hypervolume = calculate_2d_hypervolume(p1)
            best_ind = max(population, key=lambda item: item.fitness)

            history.append({
                "generation": 0,
                "best_fitness": best_ind.fitness,
                "hypervolume": self.last_hypervolume,
                "pareto_count": len(p1),
                "evaluations": self.evaluations,
                "llm_calls": self.llm_calls,
            })

            # 2. Evolutionary Loop with C2 Coordinator
            for gen in range(1, self.config.generations + 1):
                if self.evaluations >= self.config.max_evaluations:
                    break

                # C2 Coordinator Assessment
                failures = [ind for ind in population if ind.evaluation and ind.evaluation.get("build") != "PASSED"]
                failure_rate = len(failures) / max(1, len(population))

                curr_hv = calculate_2d_hypervolume(p1)
                hv_improvement = curr_hv - self.last_hypervolume
                if hv_improvement < 0.005:
                    self.stagnation_counter += 1
                else:
                    self.stagnation_counter = 0
                    self.last_hypervolume = curr_hv

                # C2 Decision
                c2_action = "STANDARD_EA"
                llm_candidate: ProposedIndividual | None = None

                can_call_llm = (self.llm_calls < self.config.max_llm_calls) and (self.generate is not None)

                if can_call_llm and self.stagnation_counter >= self.config.stagnation_patience:
                    c2_action = "TRIGGER_LLM_STAGNATION"
                    llm_candidate = self._call_c2_reflexion(source_text, "STAGNATION", p1, failures)
                elif can_call_llm and failure_rate >= self.config.failure_rate_threshold:
                    c2_action = "TRIGGER_LLM_FAILURE"
                    llm_candidate = self._call_c2_reflexion(source_text, "FAILURE", p1, failures)
                elif not can_call_llm and self.stagnation_counter >= self.config.stagnation_patience:
                    c2_action = "EA_DIVERSITY_INJECTION"

                c2_record = {
                    "generation": gen,
                    "action": c2_action,
                    "stagnation_counter": self.stagnation_counter,
                    "hypervolume": curr_hv,
                    "failure_rate": failure_rate,
                    "llm_calls": self.llm_calls,
                }
                self.c2_decisions.append(c2_record)
                f_c2.write(json.dumps(c2_record, ensure_ascii=False) + "\n")
                f_c2.flush()

                # Generate Offspring (Q_t)
                offspring: list[ProposedIndividual] = []
                if llm_candidate:
                    offspring.append(llm_candidate)
                elif c2_action == "EA_DIVERSITY_INJECTION":
                    offspring.append(self._random_individual(origin="ea_diversity"))

                while len(offspring) < self.config.population_size:
                    parent1 = self._tournament(population)
                    parent2 = self._tournament(population)
                    child1, child2 = self._crossover(parent1, parent2)
                    for child in (self._mutate(child1), self._mutate(child2)):
                        child.origin = "ea"
                        offspring.append(child)
                        if len(offspring) == self.config.population_size:
                            break

                # Evaluate Offspring
                gen_dir = output / "candidates" / f"generation-{gen:03d}"
                gen_dir.mkdir(parents=True, exist_ok=True)
                for idx, ind in enumerate(offspring):
                    cand = gen_dir / f"candidate-{idx:03d}.c"
                    try:
                        self._evaluate_individual(ind, source, cand)
                    except StopIteration:
                        break
                    except Exception as err:
                        ind.objectives = (0.0, 0.0)
                        ind.fitness = 0.0
                        ind.evaluation = {"build": "BUILD_FAIL", "error": str(err)}
                    rec = {
                        "generation": gen,
                        "candidate": idx,
                        "origin": ind.origin,
                        "thought": ind.thought,
                        "genes": [asdict(g) for g in ind.genes],
                        "fitness": ind.fitness,
                        "objectives": ind.objectives,
                        "evaluation": ind.evaluation,
                    }
                    f_eval.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    f_eval.flush()

                # NSGA-II Environmental Selection: R_t = P_t + Q_t -> P_{t+1}
                combined = population + offspring
                population = environmental_selection(combined, self.config.population_size)

                fronts = fast_non_dominated_sort(population)
                p1 = fronts[0] if fronts else []
                assign_crowding_distance(p1)
                best_ind = max(population, key=lambda item: item.fitness)

                history.append({
                    "generation": gen,
                    "best_fitness": best_ind.fitness,
                    "hypervolume": calculate_2d_hypervolume(p1),
                    "pareto_count": len(p1),
                    "evaluations": self.evaluations,
                    "llm_calls": self.llm_calls,
                })

        # Save Best and Pareto Front
        best_overall = max(population, key=lambda ind: ind.fitness)
        if best_overall.source and Path(best_overall.source).is_file():
            shutil.copyfile(best_overall.source, output / "best.c")
        else:
            shutil.copyfile(source, output / "best.c")

        # Mirror ../common and sibling headers to output directory so best.c can be compiled/scored standalone
        for item in source.parent.iterdir():
            if item.name == source.name or item.name == "candidates" or item.name == "output":
                continue
            target = output / item.name
            if item.is_dir() and not target.exists():
                shutil.copytree(item, target, dirs_exist_ok=True, ignore=shutil.ignore_patterns("candidates", "output"))
            elif item.is_file() and not target.exists():
                shutil.copyfile(item, target)
        if "../" in (output / "best.c").read_text(encoding="utf-8", errors="replace"):
            parent_dir = source.parent.parent
            for item in parent_dir.iterdir():
                if item.name == source.parent.name or item.name == "candidates" or item.name == "output":
                    continue
                target = output.parent / item.name
                if item.is_dir() and not target.exists():
                    shutil.copytree(item, target, dirs_exist_ok=True, ignore=shutil.ignore_patterns("candidates", "output"))
                elif item.is_file() and not target.exists():
                    shutil.copyfile(item, target)

        pareto_front_export = [
            {
                "genes": [asdict(g) for g in ind.genes],
                "objectives": {"fitness": ind.objectives[0], "compactness": ind.objectives[1]},
                "fitness": ind.fitness,
                "origin": ind.origin,
                "thought": ind.thought,
                "source": ind.source,
            }
            for ind in p1
        ]

        result = {
            "input": str(source),
            "best_source": str(output / "best.c"),
            "best_fitness": best_overall.fitness,
            "best_objectives": best_overall.objectives,
            "best_genes": [asdict(g) for g in best_overall.genes],
            "best_origin": best_overall.origin,
            "pareto_front": pareto_front_export,
            "evaluations": self.evaluations,
            "llm_calls": self.llm_calls,
            "history": history,
            "c2_decisions": self.c2_decisions,
            "config": asdict(self.config),
            "evaluations_file": str(evaluations_log),
            "c2_file": str(c2_log),
        }
        (output / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return result
