from __future__ import annotations

import hashlib
import json
import math
import random
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from .operators import Gene, TigressPool


@dataclass(frozen=True)
class GAConfig:
    population_size: int = 8
    generations: int = 5
    chromosome_length: int = 6
    tournament_size: int = 3
    crossover_rate: float = 0.70
    mutation_rate: float = 0.20
    noop_rate: float = 0.25
    convergence_threshold: float = 0.02
    patience: int = 3
    max_evaluations: int = 48
    seed: int = 0

    def __post_init__(self):
        integers = (self.population_size, self.generations, self.chromosome_length, self.tournament_size, self.patience, self.max_evaluations)
        if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in integers):
            raise ValueError("GA integer settings must be positive")
        if self.tournament_size > self.population_size:
            raise ValueError("tournament_size cannot exceed population_size")
        for name in ("crossover_rate", "mutation_rate", "noop_rate"):
            value = getattr(self, name)
            if not isinstance(value, (int, float)) or not 0 <= value <= 1:
                raise ValueError(f"{name} must be within [0, 1]")
        if not isinstance(self.convergence_threshold, (int, float)) or self.convergence_threshold < 0:
            raise ValueError("convergence_threshold must be non-negative")


@dataclass
class Individual:
    genes: tuple[Gene, ...]
    fitness: float | None = None
    source: str | None = None
    evaluation: dict | None = None

    @property
    def key(self):
        return tuple((gene.operator, gene.seed) for gene in self.genes)


Evaluator = Callable[[Path], tuple[float, dict]]


class GARunner:
    def __init__(self, pool: TigressPool, evaluator: Evaluator, config: GAConfig | None = None):
        self.pool = pool
        self.evaluator = evaluator
        self.config = config or GAConfig()
        self.random = random.Random(self.config.seed)
        self.evaluations = 0
        self._source_cache: dict[str, tuple[float, dict]] = {}

    def _gene(self) -> Gene:
        if self.random.random() < self.config.noop_rate:
            return Gene("noop", 0)
        return Gene(self.random.choice(tuple(self.pool.operators)), self.random.randrange(2**31))

    def _individual(self) -> Individual:
        return Individual(tuple(self._gene() for _ in range(self.config.chromosome_length)))

    def _tournament(self, population: list[Individual]) -> Individual:
        return max(self.random.sample(population, self.config.tournament_size), key=lambda item: item.fitness)

    def _crossover(self, left: Individual, right: Individual) -> tuple[Individual, Individual]:
        if self.random.random() >= self.config.crossover_rate:
            return Individual(left.genes), Individual(right.genes)
        first, second = [], []
        for a, b in zip(left.genes, right.genes):
            if self.random.random() < 0.5:
                first.append(a)
                second.append(b)
            else:
                first.append(b)
                second.append(a)
        return Individual(tuple(first)), Individual(tuple(second))

    def _mutate(self, individual: Individual) -> Individual:
        if self.random.random() >= self.config.mutation_rate:
            return individual
        genes = list(individual.genes)
        genes[self.random.randrange(len(genes))] = self._gene()
        return Individual(tuple(genes))

    def _evaluate(self, individual: Individual, original: Path, candidate: Path) -> Individual:
        trace = self.pool.transform(original, individual.genes, candidate)
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
        individual.fitness = float(fitness)
        individual.source = str(candidate)
        individual.evaluation = {**details, "source_sha256": digest, "trace": trace}
        return individual

    def _evaluate_generation(self, population: list[Individual], original: Path, root: Path, generation: int) -> list[Individual]:
        directory = root / "candidates" / f"generation-{generation:03d}"
        evaluated = []
        for index, individual in enumerate(population):
            candidate = directory / f"candidate-{index:03d}.c"
            try:
                evaluated.append(self._evaluate(individual, original, candidate))
            except StopIteration:
                break
            except Exception as error:
                individual.fitness = float("-inf")
                individual.source = str(candidate)
                individual.evaluation = {"status": "TRANSFORM_ERROR", "error": str(error)}
                evaluated.append(individual)
        return evaluated

    def run(self, source: Path, output: Path) -> dict:
        source = Path(source).resolve()
        output = Path(output).resolve()
        if not source.is_file() or source.suffix.lower() != ".c":
            raise ValueError(f"Expected an existing .c source: {source}")
        if output.exists() and (not output.is_dir() or any(output.iterdir())):
            raise ValueError(f"Output directory must be an empty directory: {output}")
        output.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, output / "original.c")

        population = [self._individual() for _ in range(self.config.population_size)]
        population = self._evaluate_generation(population, source, output, 0)
        if not population or all(item.fitness == float("-inf") for item in population):
            raise RuntimeError("No candidate could be transformed and evaluated")
        best = max(population, key=lambda item: item.fitness)
        history = [{"generation": 0, "best_fitness": best.fitness, "evaluations": self.evaluations}]
        stale = 0

        for generation in range(1, self.config.generations + 1):
            if self.evaluations >= self.config.max_evaluations:
                break
            children = []
            while len(children) < self.config.population_size:
                left, right = self._crossover(self._tournament(population), self._tournament(population))
                children.extend((self._mutate(left), self._mutate(right)))
            evaluated = self._evaluate_generation(children[:self.config.population_size], source, output, generation)
            if not evaluated:
                break
            population = sorted(population + evaluated, key=lambda item: item.fitness, reverse=True)[:self.config.population_size]
            current = population[0]
            improvement = current.fitness - best.fitness
            if improvement > 0:
                best = current
            stale = 0 if improvement >= self.config.convergence_threshold else stale + 1
            history.append({"generation": generation, "best_fitness": best.fitness, "evaluations": self.evaluations})
            if stale >= self.config.patience:
                break

        best_source = output / "best.c"
        shutil.copyfile(best.source, best_source)
        result = {
            "input": str(source),
            "best_source": str(best_source),
            "best_fitness": best.fitness,
            "best_genes": [asdict(gene) for gene in best.genes if gene.operator != "noop"],
            "best_evaluation": best.evaluation,
            "evaluations": self.evaluations,
            "history": history,
            "config": asdict(self.config),
        }
        (output / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return result
