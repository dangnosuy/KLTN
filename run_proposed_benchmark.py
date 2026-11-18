#!/usr/bin/env python3
"""Dedicated benchmark runner for Proposed Method (C2 + NSGA-II + Qwen 3.8-27b Reflexion)."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

ROOT = Path("/home/dangnosuy/Documents/UIT/KLTN")
PYTHON = Path.home() / "Documents/venv/bin/python3"
RESULTS_DIR = ROOT / "baseline_results/proposed_qwen_benchmark"
POOL = ROOT / "pipeline/mutators/native_pool.json"
SCORE_CMD = f"{PYTHON} -m pipeline.ga_only.static_score {{source}} --engines clamav,ember,malconv"
MODEL = "cf/@cf/qwen/qwen3.8-27b"

TARGETS = [
    ROOT / "dataset/advanced/sources/baseline/local_exec_xor.c",
    ROOT / "dataset/advanced/sources/baseline/map_view_xor.c",
    ROOT / "dataset/advanced/sources/baseline/unhook_exec_xor.c",
    ROOT / "dataset/advanced/sources/experimental/process_hollow.c",
    ROOT / "dataset/advanced/sources/experimental/reflective_injection.c",
]


def extract_score(eval_dict: dict, engine: str, default: float) -> float:
    try:
        return float(eval_dict.get("detectors", {}).get(engine, {}).get("score", default))
    except Exception:
        return default


def run_target(sample: Path) -> dict:
    stem = sample.stem
    print(f"\n=======================================================", flush=True)
    print(f"  Running Proposed (Qwen 3.8-27b) on: {stem}", flush=True)
    print(f"=======================================================", flush=True)

    out_dir = RESULTS_DIR / stem
    res_file = out_dir / "result.json"

    # Step 1: Baseline / Ground Truth scoring
    score_orig_cmd = [
        str(PYTHON), "-m", "pipeline.ga_only.static_score",
        str(sample), "--engines", "clamav,ember,malconv"
    ]
    p_orig = subprocess.run(score_orig_cmd, cwd=ROOT, capture_output=True, text=True, timeout=120)
    orig_eval = json.loads(p_orig.stdout) if p_orig.returncode == 0 else {}
    orig_ember = extract_score(orig_eval, "ember", 1.0)
    orig_fitness = orig_eval.get("fitness", 0.0)
    print(f"  [Original] Fitness: {orig_fitness:.4f} | EMBER: {orig_ember:.4f}", flush=True)

    # Step 2: Run Proposed NSGA-II + C2 Reflexion
    shutil.rmtree(out_dir, ignore_errors=True)
    cmd = [
        str(PYTHON), "-m", "pipeline.proposed", "run", str(sample),
        "--pool", str(POOL),
        "--output", str(out_dir),
        "--score-command", SCORE_CMD,
        "--population-size", "4",
        "--generations", "2",
        "--chromosome-length", "2",
        "--stagnation-patience", "1",
        "--max-llm-calls", "2",
        "--model", MODEL,
        "--seed", "42",
    ]
    t0 = time.time()
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=360)
    elapsed = time.time() - t0

    if res_file.is_file():
        res = json.loads(res_file.read_text())
        best_c = out_dir / "best.c"

        # Re-score best.c for clean validation
        p_best = subprocess.run([
            str(PYTHON), "-m", "pipeline.ga_only.static_score",
            str(best_c), "--engines", "clamav,ember,malconv"
        ], cwd=ROOT, capture_output=True, text=True, timeout=120)
        best_eval = json.loads(p_best.stdout) if p_best.returncode == 0 else {}

        best_ember = extract_score(best_eval, "ember", 1.0)
        best_fitness = best_eval.get("fitness", res.get("best_fitness", 0.0))
        delta_ember = best_ember - orig_ember

        record = {
            "target": stem,
            "original_fitness": round(orig_fitness, 4),
            "original_ember": round(orig_ember, 4),
            "best_fitness": round(best_fitness, 4),
            "best_ember": round(best_ember, 4),
            "delta_ember": round(delta_ember, 4),
            "clamav_detected": best_eval.get("detectors", {}).get("clamav", {}).get("detected", False),
            "malconv_score": extract_score(best_eval, "malconv", 0.0),
            "best_origin": res.get("best_origin", ""),
            "best_genes": res.get("best_genes", []),
            "pareto_front_size": len(res.get("pareto_front", [])),
            "llm_calls": res.get("llm_calls", 0),
            "c2_decisions": res.get("c2_decisions", []),
            "elapsed_seconds": round(elapsed, 1),
        }
        print(f"  [Proposed] Best Fitness: {record['best_fitness']:.4f} | EMBER: {record['best_ember']:.4f} (Δ: {record['delta_ember']:+.4f}) | Origin: {record['best_origin']} | LLM calls: {record['llm_calls']} ({elapsed:.1f}s)", flush=True)
        return record
    else:
        print(f"  [Proposed] FAILED ({elapsed:.1f}s): {proc.stderr[-300:]}", flush=True)
        return {
            "target": stem,
            "original_fitness": round(orig_fitness, 4),
            "original_ember": round(orig_ember, 4),
            "error": proc.stderr[-300:],
            "elapsed_seconds": round(elapsed, 1),
        }


def main():
    print(f"Starting Proposed (Qwen 3.8-27b) Benchmark Suite at {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Targets ({len(TARGETS)}): {[t.stem for t in TARGETS]}")
    t_start = time.time()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    summary = {}

    for target in TARGETS:
        summary[target.stem] = run_target(target)
        # Checkpoint after each target
        (RESULTS_DIR / "summary.json").write_text(json.dumps(summary, indent=2))

    total_time = round(time.time() - t_start, 1)
    print(f"\n=======================================================", flush=True)
    print(f"  All targets completed in {total_time}s", flush=True)
    print(f"  Summary saved to: {RESULTS_DIR / 'summary.json'}", flush=True)
    print(f"=======================================================", flush=True)


if __name__ == "__main__":
    main()
