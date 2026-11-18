from __future__ import annotations

import argparse
import json
from pathlib import Path

from pipeline.ga_only.__main__ import command_evaluator
from pipeline.ga_only.operators import TigressPool
from pipeline.single_agent.__main__ import DEFAULT_BASE_URL, DEFAULT_MODEL
from pipeline.single_agent.openai_compatible import OpenAICompatibleClient

from .algorithm import ProposedConfig, ProposedRunner


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Proposed Baseline (C2 Cost-Aware Coordinator + NSGA-II Multi-Objective + LLM Reflexion)"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    doctor = commands.add_parser("doctor")
    doctor.add_argument("--pool", type=Path, required=True)
    doctor.add_argument("--model", default=DEFAULT_MODEL)
    doctor.add_argument("--base-url", default=DEFAULT_BASE_URL)

    run = commands.add_parser("run")
    run.add_argument("source", type=Path)
    run.add_argument("--pool", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--score-command", required=True, help="Command printing JSON with fitness; use {source} placeholder")
    run.add_argument("--population-size", type=int, default=8)
    run.add_argument("--generations", type=int, default=5)
    run.add_argument("--chromosome-length", type=int, default=4)
    run.add_argument("--stagnation-patience", type=int, default=2)
    run.add_argument("--failure-rate-threshold", type=float, default=0.50)
    run.add_argument("--max-llm-calls", type=int, default=6)
    run.add_argument("--max-evaluations", type=int, default=48)
    run.add_argument("--model", default=DEFAULT_MODEL)
    run.add_argument("--base-url", default=DEFAULT_BASE_URL)
    run.add_argument("--seed", type=int, default=0)
    run.add_argument("--no-llm", action="store_true", help="Run pure NSGA-II without LLM Reflexion")

    args = parser.parse_args(argv)

    try:
        pool = TigressPool.load(args.pool)
        pool_status = pool.doctor()

        client = None
        if not getattr(args, "no_llm", False):
            client = OpenAICompatibleClient(args.model, args.base_url)

        if args.command == "doctor":
            llm_status = client.doctor() if client else {"ready": True, "note": "LLM disabled"}
            report = {
                "pool": pool_status,
                "llm": llm_status,
                "ready": pool_status["ready"] and llm_status.get("ready", False),
            }
            print(json.dumps(report, indent=2, ensure_ascii=False), flush=True)
            return 0 if report["ready"] else 2

        if not pool_status["ready"]:
            raise RuntimeError(f"Tigress binary unavailable: {pool.binary}")

        config = ProposedConfig(
            population_size=args.population_size,
            generations=args.generations,
            chromosome_length=args.chromosome_length,
            stagnation_patience=args.stagnation_patience,
            failure_rate_threshold=args.failure_rate_threshold,
            max_llm_calls=0 if args.no_llm else args.max_llm_calls,
            max_evaluations=args.max_evaluations,
            seed=args.seed,
        )

        generate_fn = client.generate if client and not args.no_llm else None
        runner = ProposedRunner(
            pool=pool,
            evaluator=command_evaluator(args.score_command),
            generate=generate_fn,
            config=config,
        )

        result = runner.run(args.source, args.output)
        print(json.dumps(result, indent=2, ensure_ascii=False), flush=True)
        return 0

    except (Exception, KeyboardInterrupt) as error:
        print(f"ERROR: {error}", flush=True)
        return 130 if isinstance(error, KeyboardInterrupt) else 2


if __name__ == "__main__":
    raise SystemExit(main())
