from __future__ import annotations

import argparse
import json
import shlex
import subprocess
from pathlib import Path

from .algorithm import GAConfig, GARunner
from .operators import TigressPool


def command_evaluator(template: str):
    template_parts = shlex.split(template)
    if all("{source}" not in part for part in template_parts):
        raise ValueError("Score command must contain {source}")

    def evaluate(source: Path):
        command = [part.replace("{source}", str(source)) for part in template_parts]
        process = subprocess.run(command, capture_output=True, text=True, timeout=1800)
        if process.returncode:
            raise RuntimeError((process.stderr or process.stdout or "Score command failed")[-1500:])
        result = json.loads(process.stdout)
        if not isinstance(result, dict) or "fitness" not in result:
            raise ValueError("Score command must print a JSON object containing fitness")
        return result["fitness"], {key: value for key, value in result.items() if key != "fitness"}
    return evaluate


def main(argv=None):
    parser = argparse.ArgumentParser(description="GA-only C source transformation baseline")
    commands = parser.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor")
    doctor.add_argument("--pool", type=Path, required=True)
    run = commands.add_parser("run")
    run.add_argument("source", type=Path)
    run.add_argument("--pool", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--score-command", required=True, help="Command printing JSON with fitness; use {source} placeholder")
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
        result = GARunner(pool, command_evaluator(args.score_command), GAConfig(seed=args.seed)).run(args.source, args.output)
        print(json.dumps(result, indent=2, ensure_ascii=False), flush=True)
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print(f"ERROR: {error}", flush=True)
        return 130 if isinstance(error, KeyboardInterrupt) else 2


if __name__ == "__main__":
    raise SystemExit(main())
