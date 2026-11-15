import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from .core import ENGINES, load_config
from .runner import DetectorRunner, safe_error


def main(argv=None):
    parser = argparse.ArgumentParser(description="Five-detector thesis pipeline: static AV/ML and CAPE behavior")
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("doctor", "run"):
        sub = commands.add_parser(command)
        sub.add_argument("--config", type=Path, help="JSON config; paths are relative to workspace root")
        sub.add_argument("--engines", default=",".join(ENGINES), help="Comma-separated engine names")
        if command == "run":
            sub.add_argument("target", type=Path, help="EXE or directory of EXE files")
            sub.add_argument("--campaign", default=datetime.now(timezone.utc).strftime("detectors-%Y%m%dT%H%M%S%fZ"))
            sub.add_argument("--c1", type=Path, help="Optional external C1 JSON for a single EXE")
    args = parser.parse_args(argv)
    engines = args.engines.split(",")
    if not engines or len(engines) != len(set(engines)) or set(engines) - set(ENGINES):
        parser.error("--engines must contain distinct names from " + ",".join(ENGINES))
    # Enforce the same resource-friendly execution order regardless of argument order.
    engines = [engine for engine in ENGINES if engine in engines]
    runner = None
    exit_code = 0
    try:
        runner = DetectorRunner(load_config(args.config))
        if args.command == "doctor":
            report = runner.doctor(engines)
            print(json.dumps(report, indent=2, ensure_ascii=False), flush=True)
            exit_code = 0 if report["ready"] else 2
        else:
            summary = runner.run(args.target, args.campaign, engines, args.c1)
            exit_code = 2 if summary["counts"]["errors"] else 0
    except (Exception, KeyboardInterrupt) as error:
        print("ERROR: " + (safe_error(error) or "Interrupted; completed results/task IDs retained"), flush=True)
        exit_code = 130 if isinstance(error, KeyboardInterrupt) else 2
    finally:
        if runner:
            try:
                runner.close()
            except Exception as error:
                print("ERROR during shutdown: " + safe_error(error), flush=True)
                exit_code = 2
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
