from __future__ import annotations

import argparse
import json
from pathlib import Path

from pipeline.ga_only.__main__ import command_evaluator

from .algorithm import ReflexionConfig, ReflexionRunner
from .openai_compatible import OpenAICompatibleClient


DEFAULT_MODEL = "cf/@cf/qwen/qwen3.8-27b"
DEFAULT_BASE_URL = "http://127.0.0.1:20128/v1"


def detector_success(target: str):
    def success(feedback: dict) -> bool:
        if feedback.get("build") != "PASSED":
            return False
        report = feedback.get("detectors", {}).get(target)
        if not isinstance(report, dict) or report.get("status") != "COMPLETED" or not isinstance(report.get("detected"), bool):
            raise ValueError(f"Evaluator did not return a completed {target} result")
        return not report["detected"]
    return success


def main(argv=None):
    parser = argparse.ArgumentParser(description="Reflexion-style single-agent C source baseline")
    commands = parser.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor")
    doctor.add_argument("--model", default=DEFAULT_MODEL)
    doctor.add_argument("--base-url", default=DEFAULT_BASE_URL)
    run = commands.add_parser("run")
    run.add_argument("source", type=Path)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--score-command", required=True, help="Command printing JSON with fitness; use {source} placeholder")
    run.add_argument("--target", choices=("clamav", "ember"), default="ember")
    run.add_argument("--max-attempts", type=int, default=5)
    run.add_argument("--model", default=DEFAULT_MODEL)
    run.add_argument("--base-url", default=DEFAULT_BASE_URL)
    args = parser.parse_args(argv)

    try:
        client = OpenAICompatibleClient(args.model, args.base_url)
        health = client.doctor()
        if args.command == "doctor":
            print(json.dumps(health, indent=2, ensure_ascii=False), flush=True)
            return 0 if health["ready"] else 2
        if not health["ready"]:
            raise RuntimeError(health.get("error") or f"LLM model is unavailable: {args.model}")
        runner = ReflexionRunner(
            client.generate,
            command_evaluator(args.score_command),
            detector_success(args.target),
            ReflexionConfig(max_attempts=args.max_attempts, target=args.target),
        )
        result = runner.run(args.source, args.output)
        print(json.dumps(result, indent=2, ensure_ascii=False), flush=True)
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print(f"ERROR: {error}", flush=True)
        return 130 if isinstance(error, KeyboardInterrupt) else 2


if __name__ == "__main__":
    raise SystemExit(main())
