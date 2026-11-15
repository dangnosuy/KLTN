from __future__ import annotations

import argparse
import json
from pathlib import Path

from pipeline.ga_only.__main__ import command_evaluator
from pipeline.ga_only.operators import TigressPool

from .algorithm import HeuristicRunner, Recipe


def main(argv=None):
    parser = argparse.ArgumentParser(description="Deterministic C source transformation baseline")
    commands = parser.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor")
    doctor.add_argument("--pool", type=Path, required=True)
    run = commands.add_parser("run")
    run.add_argument("source", type=Path)
    run.add_argument("--pool", type=Path, required=True)
    run.add_argument("--recipe", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--score-command", required=True, help="Command printing JSON with fitness; use {source} placeholder")
    args = parser.parse_args(argv)
    try:
        pool = TigressPool.load(args.pool)
        if args.command == "doctor":
            report = pool.doctor()
            print(json.dumps(report, indent=2), flush=True)
            return 0 if report["ready"] else 2
        if not pool.doctor()["ready"]:
            raise RuntimeError(f"Tigress binary not found: {pool.binary}")
        result = HeuristicRunner(pool, command_evaluator(args.score_command)).run(args.source, Recipe.load(args.recipe), args.output)
        print(json.dumps(result, indent=2, ensure_ascii=False), flush=True)
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print(f"ERROR: {error}", flush=True)
        return 130 if isinstance(error, KeyboardInterrupt) else 2


if __name__ == "__main__":
    raise SystemExit(main())

