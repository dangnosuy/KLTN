from __future__ import annotations

import argparse
import json
from pathlib import Path

from pipeline.ga_only.__main__ import command_evaluator
from pipeline.ga_only.algorithm import GAConfig
from pipeline.ga_only.operators import TigressPool
from pipeline.single_agent.__main__ import DEFAULT_BASE_URL, DEFAULT_MODEL
from pipeline.single_agent.openai_compatible import OpenAICompatibleClient

from .algorithm import FixedHybridConfig, FixedHybridRunner


def main(argv=None):
    parser = argparse.ArgumentParser(description="Fixed-schedule EoH-inspired GA + LLM baseline")
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
    run.add_argument("--chromosome-length", type=int, default=6)
    run.add_argument("--max-evaluations", type=int, default=48)
    run.add_argument("--llm-fraction", type=float, default=0.25)
    run.add_argument("--seed", type=int, default=0)
    run.add_argument("--model", default=DEFAULT_MODEL)
    run.add_argument("--base-url", default=DEFAULT_BASE_URL)
    args = parser.parse_args(argv)

    try:
        pool = TigressPool.load(args.pool)
        client = OpenAICompatibleClient(args.model, args.base_url)
        health = {"pool": pool.doctor(), "llm": client.doctor()}
        health["ready"] = health["pool"]["ready"] and health["llm"]["ready"]
        if args.command == "doctor":
            print(json.dumps(health, indent=2, ensure_ascii=False), flush=True)
            return 0 if health["ready"] else 2
        if not health["ready"]:
            raise RuntimeError("Tigress or LLM service is unavailable")
        ga = GAConfig(
            population_size=args.population_size,
            generations=args.generations,
            chromosome_length=args.chromosome_length,
            tournament_size=min(3, args.population_size),
            max_evaluations=args.max_evaluations,
            seed=args.seed,
        )
        runner = FixedHybridRunner(
            pool,
            command_evaluator(args.score_command),
            client.generate,
            FixedHybridConfig(ga=ga, llm_fraction=args.llm_fraction),
        )
        result = runner.run(args.source, args.output)
        print(json.dumps(result, indent=2, ensure_ascii=False), flush=True)
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print(f"ERROR: {error}", flush=True)
        return 130 if isinstance(error, KeyboardInterrupt) else 2


if __name__ == "__main__":
    raise SystemExit(main())
