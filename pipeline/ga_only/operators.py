from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Gene:
    operator: str
    seed: int


@dataclass(frozen=True)
class Operator:
    name: str
    args: tuple[str, ...]


class TigressPool:
    def __init__(self, binary: str, environment: str, functions: tuple[str, ...], operators: tuple[Operator, ...], driver_args: tuple[str, ...] = ()):
        self.binary = binary
        self.environment = environment
        self.functions = functions
        self.operators = {operator.name: operator for operator in operators}
        self.driver_args = driver_args
        if not self.operators:
            raise ValueError("Operator pool must not be empty")

    @classmethod
    def load(cls, path: Path) -> "TigressPool":
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        required = {"binary", "environment", "functions", "operators"}
        if not isinstance(document, dict) or not required <= set(document) or set(document) - required - {"driver_args"}:
            raise ValueError("Operator pool must contain binary, environment, functions, and operators")
        binary = document["binary"]
        environment = document["environment"]
        functions = document["functions"]
        raw_operators = document["operators"]
        driver_args = document.get("driver_args", [])
        if not isinstance(binary, str) or not binary or not isinstance(environment, str) or not environment:
            raise ValueError("binary and environment must be non-empty strings")
        if not isinstance(functions, list) or not functions or not all(isinstance(item, str) and item for item in functions):
            raise ValueError("functions must be a non-empty list of names")
        if not isinstance(raw_operators, list) or not raw_operators:
            raise ValueError("operators must be a non-empty list")
        if not isinstance(driver_args, list) or not all(isinstance(arg, str) and arg for arg in driver_args):
            raise ValueError("driver_args must be a list of non-empty strings")
        operators = []
        names = set()
        for item in raw_operators:
            if not isinstance(item, dict) or set(item) != {"name", "args"}:
                raise ValueError("Each operator must contain only name and args")
            name, args = item["name"], item["args"]
            if not isinstance(name, str) or not name or name == "noop" or name in names:
                raise ValueError("Operator names must be unique, non-empty, and not 'noop'")
            if not isinstance(args, list) or not args or not all(isinstance(arg, str) and arg for arg in args):
                raise ValueError(f"Invalid args for operator {name}")
            names.add(name)
            operators.append(Operator(name, tuple(args)))
        return cls(binary, environment, tuple(functions), tuple(operators), tuple(driver_args))

    def doctor(self) -> dict:
        resolved = shutil.which(self.binary) if not Path(self.binary).is_file() else self.binary
        return {
            "ready": resolved is not None,
            "binary": self.binary,
            "resolved_binary": resolved,
            "operators": sorted(self.operators),
            "functions": list(self.functions),
            "driver_args": list(self.driver_args),
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
        if not active:
            shutil.copyfile(source, destination)
            return []

        trace = []
        with tempfile.TemporaryDirectory(prefix="ga-tigress-") as temporary:
            current = source
            for index, gene in enumerate(active):
                operator = self.operators[gene.operator]
                output = Path(temporary) / f"stage-{index:02d}.c"
                replacements = {"functions": ",".join(self.functions), "seed": str(gene.seed)}
                args = [arg.format_map(replacements) for arg in operator.args]
                command = [
                    self.binary,
                    f"--Environment={self.environment}",
                    f"--Seed={gene.seed}",
                    *self.driver_args,
                    *args,
                    f"--out={output}",
                    str(current),
                ]
                process = subprocess.run(command, capture_output=True, text=True, timeout=300)
                if process.returncode or not output.is_file():
                    message = (process.stderr or process.stdout or "Tigress produced no output").strip()
                    raise RuntimeError(f"Operator {gene.operator} failed: {message[-1500:]}")
                trace.append({"operator": gene.operator, "seed": gene.seed, "command": command[:-1] + ["<input.c>"]})
                current = output
            shutil.copyfile(current, destination)
        return trace
