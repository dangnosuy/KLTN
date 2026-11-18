from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from pipeline.ga_only.operators import Gene
from .transforms import MUTATORS


@dataclass(frozen=True)
class NativeOperator:
    name: str


class NativePool:
    def __init__(self, operators: tuple[str, ...] | None = None):
        self.binary = "native"
        self.environment = "native"
        self.functions = ("main",)
        self.driver_args = []
        op_names = operators if operators is not None else tuple(MUTATORS.keys())
        unknown = set(op_names) - set(MUTATORS.keys())
        if unknown:
            raise ValueError(f"Unknown native operators: {', '.join(sorted(unknown))}")
        self.operators = {name: NativeOperator(name) for name in op_names}
        if not self.operators:
            raise ValueError("Operator pool must not be empty")

    @classmethod
    def load(cls, path: Path) -> "NativePool":
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            raise ValueError("Invalid pool configuration JSON")
        raw_operators = document.get("operators", [])
        if not raw_operators:
            return cls()
        names = []
        for item in raw_operators:
            if isinstance(item, str):
                names.append(item)
            elif isinstance(item, dict) and "name" in item:
                names.append(item["name"])
        return cls(tuple(names))

    def doctor(self) -> dict:
        return {
            "ready": True,
            "binary": "native",
            "resolved_binary": "native",
            "operators": sorted(self.operators),
            "functions": list(self.functions),
            "driver_args": [],
        }

    def transform(self, source: Path, genes: tuple[Gene, ...], destination: Path) -> list[dict]:
        source = Path(source).resolve()
        destination = Path(destination).resolve()
        if not source.is_file() or source.suffix.lower() != ".c":
            raise ValueError(f"Expected an existing .c source: {source}")
        unknown = {gene.operator for gene in genes if gene.operator != "noop"} - set(self.operators)
        if unknown:
            raise ValueError("Unknown operators: " + ", ".join(sorted(unknown)))

        destination.parent.mkdir(parents=True, exist_ok=True)
        active = [gene for gene in genes if gene.operator != "noop"]

        code = source.read_text(encoding="utf-8", errors="replace")
        trace = []

        for gene in active:
            mutator_fn = MUTATORS.get(gene.operator)
            if mutator_fn is None:
                raise ValueError(f"Operator {gene.operator} not found in native mutators")
            code = mutator_fn(code, gene.seed)
            trace.append({
                "operator": gene.operator,
                "seed": gene.seed,
                "command": [f"native:{gene.operator}", f"--seed={gene.seed}"],
            })

        destination.write_text(code, encoding="utf-8")

        # Copy sibling header files from source directory so relative includes remain valid
        for sibling in source.parent.iterdir():
            if sibling.name == source.name:
                continue
            target = destination.parent / sibling.name
            if sibling.is_file() and not target.exists():
                shutil.copyfile(sibling, target)

        return trace
