from __future__ import annotations

import argparse
import json
from pathlib import Path

from pipeline.ga_only.__main__ import command_evaluator
from pipeline.ga_only.operators import TigressPool

from .algorithm import BanditConfig, BanditRunner


def detector_success(target):
    def success(details):
        report = details.get("detectors", {}).get(target)
        if not isinstance(report, dict) or report.get("status") != "COMPLETED" or not isinstance(report.get("detected"), bool):
            raise ValueError(f"Evaluator did not return a completed {target} result")
        return not report["detected"]
    return success


def main(argv=None):
    parser = argparse.ArgumentParser(description="Thompson-sampling C source transformation baseline")
    commands = parser.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor")
    doctor.add_argument("--pool", type=Path, required=True)
    run = commands.add_parser("run")
    run.add_argument("source", type=Path)
    run.add_argument("--pool", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--score-command", required=True, help="Command printing JSON with fitness; use {source} placeholder")
    run.add_argument("--target", choices=("clamav", "ember"), default="ember")
    run.add_argument("--budget", type=int, default=32)
    run.add_argument("--max-actions", type=int, default=6)
    run.add_argument("--seed", type=int, default=0)
    args = parser.parse_args(argv)
    try:
        pool = TigressPool.load(args.pool)
        if args.command == "doctor":
            report = pool.doctor()
            print(json.dumps(report, indent=2), flush=True)
            return 0 if report["ready"] else 2
        if not pool.doctor()["ready"]:
            raise RuntimeError(f"Tigress binary not found: {pool.binary}")
        config = BanditConfig(query_budget=args.budget, max_actions=args.max_actions, seed=args.seed)
        runner = BanditRunner(pool, command_evaluator(args.score_command), detector_success(args.target), args.target, config)
        result = runner.run(args.source, args.output)
        print(json.dumps(result, indent=2, ensure_ascii=False), flush=True)
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print(f"ERROR: {error}", flush=True)
        return 130 if isinstance(error, KeyboardInterrupt) else 2


if __name__ == "__main__":
    raise SystemExit(main())

