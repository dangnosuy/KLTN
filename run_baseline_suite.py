#!/usr/bin/env python3
"""Automated baseline benchmark runner across XOR-encoded dataset samples."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path("/home/dangnosuy/Documents/UIT/KLTN")
PYTHON = Path.home() / "Documents/venv/bin/python3"
RESULTS_DIR = ROOT / "baseline_results"
POOL = ROOT / "pipeline/ga_only/operator_pool.example.json"
RECIPE = ROOT / "pipeline/heuristic/recipe.example.json"
SCORE_CMD = f"{PYTHON} -m pipeline.ga_only.static_score {{source}} --engines clamav,ember"

SAMPLES = [
    ROOT / "dataset/advanced/sources/baseline/local_exec_xor.c",
    ROOT / "dataset/advanced/sources/baseline/map_view_xor.c",
    ROOT / "dataset/advanced/sources/baseline/anti_debug_exec_xor.c",
    ROOT / "dataset/advanced/sources/baseline/timestomp_exec_xor.c",
    ROOT / "dataset/advanced/sources/baseline/unhook_exec_xor.c",
]


def run_cmd(cmd: list[str], timeout: int = 600) -> tuple[int, str, str]:
    t0 = time.time()
    try:
        p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
        elapsed = time.time() - t0
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"Timeout after {timeout}s"
    except Exception as e:
        return 1, "", str(e)


def extract_ember_score(eval_dict: dict) -> float:
    try:
        return float(eval_dict.get("detectors", {}).get("ember", {}).get("score", 1.0))
    except Exception:
        return 1.0


def extract_clamav_detected(eval_dict: dict) -> bool:
    try:
        return bool(eval_dict.get("detectors", {}).get("clamav", {}).get("detected", True))
    except Exception:
        return True


def benchmark_baseline1_original():
    print("=== [1/6] Running Baseline 1: Original (Ground Truth) ===", flush=True)
    out_dir = RESULTS_DIR / "original"
    out_dir.mkdir(parents=True, exist_ok=True)
    records = {}
    for sample in SAMPLES:
        cmd = [str(PYTHON), "-m", "pipeline.ga_only.static_score", str(sample), "--engines", "clamav,ember"]
        code, stdout, stderr = run_cmd(cmd)
        if code == 0:
            res = json.loads(stdout)
            records[sample.name] = {
                "fitness": res.get("fitness", 0.0),
                "ember_score": extract_ember_score(res),
                "clamav_detected": extract_clamav_detected(res),
                "build": res.get("build", "FAIL"),
            }
            print(f"  {sample.name:<25}: fitness={records[sample.name]['fitness']:.4f}, ember={records[sample.name]['ember_score']:.4f}")
        else:
            print(f"  {sample.name:<25}: FAILED {stderr[:100]}")
    (out_dir / "summary.json").write_text(json.dumps(records, indent=2))
    return records


def benchmark_baseline2_random(samples: list[Path]):
    print("=== [2/7] Running Baseline 2: Random Search ===", flush=True)
    records = {}
    for sample in samples:
        out_dir = RESULTS_DIR / "random_search" / sample.stem
        shutil.rmtree(out_dir, ignore_errors=True)
        cmd = [
            str(PYTHON), "-m", "pipeline.random_search", "run", str(sample),
            "--pool", str(POOL),
            "--output", str(out_dir),
            "--score-command", SCORE_CMD,
            "--budget", "8",
            "--k-actions", "2",
            "--seed", "42",
        ]
        t0 = time.time()
        code, stdout, stderr = run_cmd(cmd, timeout=600)
        elapsed = time.time() - t0
        res_file = out_dir / "result.json"
        if res_file.is_file():
            res = json.loads(res_file.read_text())
            eval_data = res.get("best_evaluation", {})
            records[sample.name] = {
                "fitness": res.get("best_fitness", 0.0),
                "ember_score": extract_ember_score(eval_data),
                "clamav_detected": extract_clamav_detected(eval_data),
                "best_genes": res.get("best_genes", []),
                "build": eval_data.get("build", "FAIL"),
                "elapsed": elapsed,
            }
            print(f"  {sample.name:<25}: fitness={records[sample.name]['fitness']:.4f}, ember={records[sample.name]['ember_score']:.4f} ({elapsed:.1f}s)")
        else:
            print(f"  {sample.name:<25}: FAILED ({elapsed:.1f}s) {stderr[-150:]}")
    return records


def benchmark_baseline3_heuristic(samples: list[Path]):
    print("=== [3/7] Running Baseline 3: Heuristic ===", flush=True)
    records = {}
    for sample in samples:
        out_dir = RESULTS_DIR / "heuristic" / sample.stem
        shutil.rmtree(out_dir, ignore_errors=True)
        cmd = [
            str(PYTHON), "-m", "pipeline.heuristic", "run", str(sample),
            "--pool", str(POOL),
            "--recipe", str(RECIPE),
            "--output", str(out_dir),
            "--score-command", SCORE_CMD,
        ]
        t0 = time.time()
        code, stdout, stderr = run_cmd(cmd, timeout=300)
        elapsed = time.time() - t0
        res_file = out_dir / "result.json"
        if res_file.is_file():
            res = json.loads(res_file.read_text())
            eval_data = res.get("evaluation", {})
            records[sample.name] = {
                "fitness": res.get("fitness", 0.0),
                "ember_score": extract_ember_score(eval_data),
                "clamav_detected": extract_clamav_detected(eval_data),
                "build": eval_data.get("build", "FAIL"),
                "elapsed": elapsed,
            }
            print(f"  {sample.name:<25}: fitness={records[sample.name]['fitness']:.4f}, ember={records[sample.name]['ember_score']:.4f} ({elapsed:.1f}s)")
        else:
            print(f"  {sample.name:<25}: FAILED ({elapsed:.1f}s) {stderr[-150:]}")
    return records


def benchmark_baseline4_ga(samples: list[Path]):
    print("=== [4/7] Running Baseline 4: GA-only ===", flush=True)
    records = {}
    for sample in samples:
        out_dir = RESULTS_DIR / "ga_only" / sample.stem
        shutil.rmtree(out_dir, ignore_errors=True)
        cmd = [
            str(PYTHON), "-m", "pipeline.ga_only", "run", str(sample),
            "--pool", str(POOL),
            "--output", str(out_dir),
            "--score-command", SCORE_CMD,
            "--population-size", "4",
            "--generations", "2",
            "--chromosome-length", "2",
            "--max-evaluations", "8",
            "--seed", "42",
        ]
        t0 = time.time()
        code, stdout, stderr = run_cmd(cmd, timeout=300)
        elapsed = time.time() - t0
        res_file = out_dir / "result.json"
        if res_file.is_file():
            res = json.loads(res_file.read_text())
            eval_data = res.get("best_evaluation", {})
            records[sample.name] = {
                "fitness": res.get("best_fitness", 0.0),
                "ember_score": extract_ember_score(eval_data),
                "clamav_detected": extract_clamav_detected(eval_data),
                "best_genes": res.get("best_genes", []),
                "elapsed": elapsed,
            }
            print(f"  {sample.name:<25}: fitness={records[sample.name]['fitness']:.4f}, ember={records[sample.name]['ember_score']:.4f} ({elapsed:.1f}s)")
        else:
            print(f"  {sample.name:<25}: FAILED ({elapsed:.1f}s) {stderr[-150:]}")
    return records


def benchmark_baseline5_bandit(samples: list[Path]):
    print("=== [5/7] Running Baseline 5: Bandit ===", flush=True)
    records = {}
    for sample in samples:
        out_dir = RESULTS_DIR / "bandit" / sample.stem
        shutil.rmtree(out_dir, ignore_errors=True)
        cmd = [
            str(PYTHON), "-m", "pipeline.bandit", "run", str(sample),
            "--pool", str(POOL),
            "--output", str(out_dir),
            "--score-command", SCORE_CMD,
            "--budget", "8",
            "--max-actions", "2",
            "--seed", "42",
        ]
        t0 = time.time()
        code, stdout, stderr = run_cmd(cmd, timeout=300)
        elapsed = time.time() - t0
        res_file = out_dir / "result.json"
        if res_file.is_file():
            res = json.loads(res_file.read_text())
            eval_data = res.get("best_evaluation", {})
            records[sample.name] = {
                "fitness": res.get("best_fitness", 0.0),
                "baseline_fitness": res.get("baseline_fitness", 0.0),
                "ember_score": extract_ember_score(eval_data),
                "clamav_detected": extract_clamav_detected(eval_data),
                "attempts": res.get("attempt_count", 0),
                "elapsed": elapsed,
            }
            print(f"  {sample.name:<25}: fitness={records[sample.name]['fitness']:.4f}, ember={records[sample.name]['ember_score']:.4f} ({elapsed:.1f}s)")
        else:
            print(f"  {sample.name:<25}: FAILED ({elapsed:.1f}s) {stderr[-150:]}")
    return records


def benchmark_baseline6_single_agent(samples: list[Path]):
    print("=== [6/8] Running Baseline 6: Single-Agent Reflexion ===", flush=True)
    records = {}
    for sample in samples:
        out_dir = RESULTS_DIR / "single_agent" / sample.stem
        shutil.rmtree(out_dir, ignore_errors=True)
        cmd = [
            str(PYTHON), "-m", "pipeline.single_agent", "run", str(sample),
            "--output", str(out_dir),
            "--score-command", SCORE_CMD,
            "--model", "cf/@cf/qwen/qwen2.5-coder-32b-instruct",
            "--target", "ember",
            "--max-attempts", "2",
        ]
        t0 = time.time()
        code, stdout, stderr = run_cmd(cmd, timeout=300)
        elapsed = time.time() - t0
        res_file = out_dir / "result.json"
        if res_file.is_file():
            res = json.loads(res_file.read_text())
            records[sample.name] = {
                "fitness": res.get("best_fitness", 0.0),
                "baseline_fitness": res.get("baseline_fitness", 0.0),
                "attempts": res.get("attempt_count", 0),
                "elapsed": elapsed,
            }
            print(f"  {sample.name:<25}: fitness={records[sample.name]['fitness']:.4f} ({elapsed:.1f}s)")
        else:
            print(f"  {sample.name:<25}: FAILED ({elapsed:.1f}s) {stderr[-150:]}")
    return records


def benchmark_baseline7_multi_agent(samples: list[Path]):
    print("=== [7/8] Running Baseline 7: Multi-Agent ===", flush=True)
    records = {}
    for sample in samples:
        out_dir = RESULTS_DIR / "multi_agent" / sample.stem
        shutil.rmtree(out_dir, ignore_errors=True)
        cmd = [
            str(PYTHON), "-m", "pipeline.multi_agent", "run", str(sample),
            "--output", str(out_dir),
            "--score-command", SCORE_CMD,
            "--model", "cf/@cf/qwen/qwen2.5-coder-32b-instruct",
            "--target", "ember",
            "--max-attempts", "2",
        ]
        t0 = time.time()
        code, stdout, stderr = run_cmd(cmd, timeout=300)
        elapsed = time.time() - t0
        res_file = out_dir / "result.json"
        if res_file.is_file():
            res = json.loads(res_file.read_text())
            eval_data = res.get("best_evaluation", {})
            records[sample.name] = {
                "fitness": res.get("best_fitness", 0.0),
                "baseline_fitness": res.get("baseline_fitness", 0.0),
                "ember_score": extract_ember_score(eval_data),
                "clamav_detected": extract_clamav_detected(eval_data),
                "attempts": res.get("attempt_count", 0),
                "elapsed": elapsed,
            }
            print(f"  {sample.name:<25}: fitness={records[sample.name]['fitness']:.4f}, ember={records[sample.name]['ember_score']:.4f} ({elapsed:.1f}s)")
        else:
            print(f"  {sample.name:<25}: FAILED ({elapsed:.1f}s) {stderr[-150:]}")
    return records


def benchmark_baseline8_hybrid(samples: list[Path]):
    print("=== [8/9] Running Baseline 8: Hybrid-Fixed (EoH) ===", flush=True)
    records = {}
    for sample in samples:
        out_dir = RESULTS_DIR / "hybrid_fixed" / sample.stem
        shutil.rmtree(out_dir, ignore_errors=True)
        cmd = [
            str(PYTHON), "-m", "pipeline.hybrid_fixed", "run", str(sample),
            "--pool", str(POOL),
            "--output", str(out_dir),
            "--score-command", SCORE_CMD,
            "--population-size", "4",
            "--generations", "2",
            "--chromosome-length", "2",
            "--llm-fraction", "0.25",
            "--model", "ag/gemini-3.8-flash",
            "--seed", "42",
        ]
        t0 = time.time()
        code, stdout, stderr = run_cmd(cmd, timeout=300)
        elapsed = time.time() - t0
        res_file = out_dir / "result.json"
        if res_file.is_file():
            res = json.loads(res_file.read_text())
            eval_data = res.get("best_evaluation", {})
            records[sample.name] = {
                "fitness": res.get("best_fitness", 0.0),
                "ember_score": extract_ember_score(eval_data),
                "clamav_detected": extract_clamav_detected(eval_data),
                "best_origin": res.get("best_origin", ""),
                "elapsed": elapsed,
            }
            print(f"  {sample.name:<25}: fitness={records[sample.name]['fitness']:.4f}, ember={records[sample.name]['ember_score']:.4f} ({elapsed:.1f}s)")
        else:
            print(f"  {sample.name:<25}: FAILED ({elapsed:.1f}s) {stderr[-150:]}")
    return records


def benchmark_baseline9_proposed(samples: list[Path]):
    print("=== [9/9] Running Baseline 9: Proposed (C2 + NSGA-II + Reflexion) ===", flush=True)
    records = {}
    for sample in samples:
        out_dir = RESULTS_DIR / "proposed" / sample.stem
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
            "--model", "cf/@cf/qwen/qwen2.5-coder-32b-instruct",
            "--seed", "42",
        ]
        t0 = time.time()
        code, stdout, stderr = run_cmd(cmd, timeout=360)
        elapsed = time.time() - t0
        res_file = out_dir / "result.json"
        if res_file.is_file():
            res = json.loads(res_file.read_text())
            records[sample.name] = {
                "fitness": res.get("best_fitness", 0.0),
                "ember_score": 1.0 - (res.get("best_fitness", 0.0) * 2 - 1.0) if res.get("best_fitness") else 1.0,
                "best_objectives": res.get("best_objectives", []),
                "best_origin": res.get("best_origin", ""),
                "best_genes": res.get("best_genes", []),
                "pareto_front_size": len(res.get("pareto_front", [])),
                "llm_calls": res.get("llm_calls", 0),
                "c2_decisions": len(res.get("c2_decisions", [])),
                "elapsed": elapsed,
            }
            print(f"  {sample.name:<25}: fitness={records[sample.name]['fitness']:.4f}, origin={records[sample.name]['best_origin']} ({elapsed:.1f}s)")
        else:
            print(f"  {sample.name:<25}: FAILED ({elapsed:.1f}s) {stderr[-150:]}")
    return records


def main():
    print(f"Starting Baseline Benchmark Suite at {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Samples ({len(SAMPLES)}): {[s.name for s in SAMPLES]}")
    t_start = time.time()

    b1 = benchmark_baseline1_original()
    b2 = benchmark_baseline2_random(SAMPLES[:2])
    b3 = benchmark_baseline3_heuristic(SAMPLES[:2])
    b4 = benchmark_baseline4_ga(SAMPLES[:2])
    b5 = benchmark_baseline5_bandit(SAMPLES[:2])
    b6 = benchmark_baseline6_single_agent(SAMPLES[:2])
    b7 = benchmark_baseline7_multi_agent(SAMPLES[:2])
    b8 = benchmark_baseline8_hybrid(SAMPLES[:2])
    b9 = benchmark_baseline9_proposed(SAMPLES[:2])

    summary = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_elapsed_sec": round(time.time() - t_start, 1),
        "baseline1_original": b1,
        "baseline2_random": b2,
        "baseline3_heuristic": b3,
        "baseline4_ga": b4,
        "baseline5_bandit": b5,
        "baseline6_single_agent": b6,
        "baseline7_multi_agent": b7,
        "baseline8_hybrid_fixed": b8,
        "baseline9_proposed": b9,
    }

    out_file = RESULTS_DIR / "final_benchmark_summary.json"
    out_file.write_text(json.dumps(summary, indent=2))
    print(f"\nAll done in {summary['total_elapsed_sec']}s. Summary saved to {out_file}")


if __name__ == "__main__":
    main()
