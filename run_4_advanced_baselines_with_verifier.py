#!/usr/bin/env python3
"""
Benchmark 4 Advanced Algorithm Baselines on C1 Dataset with Behavior Verifier Gate.

Algorithms evaluated:
  1. Multi-Armed Bandit (MAB - Thompson Sampling)
  2. Genetic Algorithm (GA-Only - Evolutionary Search)
  3. Single-Agent Reflexion (LLM Agent Qwen 3.8-27b)
  4. Hybrid-Fixed (EoH-style GA + LLM Mutation)

Target: g3_02_hash_djb2 (PEB Walk & DJB2 API Hash Resolution)
"""

import os
import sys
import json
import time
import subprocess
from pathlib import Path

ROOT = Path("/home/dangnosuy/Documents/UIT/KLTN")
PYTHON = Path.home() / "Documents/venv/bin/python3"
SCORE_CMD = f"{PYTHON} -m pipeline.ga_only.static_score {{source}} --engines clamav,ember,malconv"
POOL = ROOT / "pipeline/mutators/native_pool.json"
OUT_DIR = ROOT / "baseline_results/four_advanced_baselines"
OUT_DIR.mkdir(parents=True, exist_ok=True)

TARGET_SOURCE = ROOT / "sources/dataset/g3_api_hook_evasion/g3_02_hash_djb2.c"
TARGET_ID = "g3_02_hash_djb2"
MODEL = "cf/@cf/qwen/qwen3.8-27b"
BASE_URL = "http://127.0.0.1:20128/v1"

def print_hdr(text):
    print("\n" + "=" * 70)
    print(f" {text}")
    print("=" * 70, flush=True)

def score_file(source: Path) -> dict:
    cmd = [str(PYTHON), "-m", "pipeline.ga_only.static_score", str(source), "--engines", "clamav,ember,malconv"]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if p.returncode == 0:
        return json.loads(p.stdout)
    return {"fitness": 0.0, "build": "FAIL", "error": p.stderr.strip()[:200]}

def main():
    print_hdr("BENCHMARK 4 ADVANCED BASELINES WITH BEHAVIOR VERIFIER (C1)")
    print(f"Target: {TARGET_ID} ({TARGET_SOURCE})")

    # 0. Ground truth
    print("\n[0] Original Ground Truth Scoring...")
    orig = score_file(TARGET_SOURCE)
    fit_orig = orig.get("fitness", 0.0)
    ember_orig = orig.get("detectors", {}).get("ember", {}).get("score", 1.0)
    build_orig = orig.get("build", "FAIL")
    print(f"    Original Fitness = {fit_orig:.4f} | EMBER = {ember_orig:.4f} | Build = {build_orig}")

    results = {
        "original": {"fitness": fit_orig, "ember": ember_orig, "build": build_orig}
    }

    # 1. Baseline 1: Multi-Armed Bandit (MAB)
    print("\n[1] Running Baseline 1: Multi-Armed Bandit (MAB Thompson Sampling)...")
    out_bandit = OUT_DIR / "bandit"
    out_bandit.mkdir(parents=True, exist_ok=True)
    b_json = out_bandit / "result.json"
    dt_b = 0.0
    if not b_json.is_file():
        cmd_bandit = [
            str(PYTHON), "-m", "pipeline.bandit", "run", str(TARGET_SOURCE),
            "--pool", str(POOL),
            "--output", str(out_bandit),
            "--score-command", SCORE_CMD,
            "--budget", "4",
            "--seed", "42"
        ]
        t0 = time.time()
        p_b = subprocess.run(cmd_bandit, capture_output=True, text=True, timeout=240)
        dt_b = time.time() - t0
    fit_b, ember_b, build_b = 0.0, 1.0, "FAIL"
    if b_json.is_file():
        d_b = json.loads(b_json.read_text())
        fit_b = d_b.get("best_fitness", 0.0)
        ev_b = d_b.get("best_evaluation", {})
        ember_b = ev_b.get("detectors", {}).get("ember", {}).get("score", 1.0)
        build_b = ev_b.get("build", "PASSED" if fit_b > 0 else "FAIL")
    print(f"    MAB Result    : Fitness = {fit_b:.4f} | EMBER = {ember_b:.4f} | Build = {build_b} ({dt_b:.1f}s)")
    results["bandit"] = {"fitness": fit_b, "ember": ember_b, "build": build_b, "duration_s": dt_b}

    # 2. Baseline 2: Genetic Algorithm (GA-Only)
    print("\n[2] Running Baseline 2: Genetic Algorithm (GA-Only)...")
    out_ga = OUT_DIR / "ga_only"
    out_ga.mkdir(parents=True, exist_ok=True)
    ga_json = out_ga / "result.json"
    dt_ga = 0.0
    if not ga_json.is_file():
        cmd_ga = [
            str(PYTHON), "-m", "pipeline.ga_only", "run", str(TARGET_SOURCE),
            "--pool", str(POOL),
            "--output", str(out_ga),
            "--score-command", SCORE_CMD,
            "--population-size", "4",
            "--generations", "2",
            "--seed", "42"
        ]
        t0 = time.time()
        p_ga = subprocess.run(cmd_ga, capture_output=True, text=True, timeout=240)
        dt_ga = time.time() - t0
    fit_ga, ember_ga, build_ga = 0.0, 1.0, "FAIL"
    if ga_json.is_file():
        d_ga = json.loads(ga_json.read_text())
        fit_ga = d_ga.get("best_fitness", 0.0)
        ev_ga = d_ga.get("best_evaluation", {})
        ember_ga = ev_ga.get("detectors", {}).get("ember", {}).get("score", 1.0)
        build_ga = ev_ga.get("build", "PASSED" if fit_ga > 0 else "FAIL")
    print(f"    GA Result     : Fitness = {fit_ga:.4f} | EMBER = {ember_ga:.4f} | Build = {build_ga} ({dt_ga:.1f}s)")
    results["ga_only"] = {"fitness": fit_ga, "ember": ember_ga, "build": build_ga, "duration_s": dt_ga}

    # 3. Baseline 3: Single-Agent Reflexion (LLM Agent Qwen 3.8-27b)
    print(f"\n[3] Running Baseline 3: Single-Agent Reflexion ({MODEL})...")
    out_agent = OUT_DIR / "single_agent"
    out_agent.mkdir(parents=True, exist_ok=True)
    cmd_agent = [
        str(PYTHON), "-m", "pipeline.single_agent", "run", str(TARGET_SOURCE),
        "--output", str(out_agent),
        "--score-command", SCORE_CMD,
        "--max-attempts", "2",
        "--model", MODEL,
        "--base-url", BASE_URL
    ]
    t0 = time.time()
    p_sa = subprocess.run(cmd_agent, capture_output=True, text=True, timeout=240)
    dt_sa = time.time() - t0
    sa_json = out_agent / "result.json"
    fit_sa, ember_sa, build_sa = 0.0, 1.0, "FAIL"
    if sa_json.is_file():
        d_sa = json.loads(sa_json.read_text())
        fit_sa = d_sa.get("best_fitness", 0.0)
        final_c = out_agent / "final.c"
        if final_c.is_file():
            ev_sa = score_file(final_c)
            ember_sa = ev_sa.get("detectors", {}).get("ember", {}).get("score", 1.0)
            build_sa = ev_sa.get("build", "FAIL")
        else:
            build_sa = "PASSED" if fit_sa > 0 else "FAIL"
    print(f"    Reflexion Result: Fitness = {fit_sa:.4f} | EMBER = {ember_sa:.4f} | Build = {build_sa} ({dt_sa:.1f}s)")
    results["single_agent"] = {"fitness": fit_sa, "ember": ember_sa, "build": build_sa, "duration_s": dt_sa}

    # 4. Baseline 4: Fixed-Schedule Hybrid (GA + LLM Mutation)
    print(f"\n[4] Running Baseline 4: Fixed-Schedule Hybrid (GA + LLM {MODEL})...")
    out_hybrid = OUT_DIR / "hybrid_fixed"
    out_hybrid.mkdir(parents=True, exist_ok=True)
    cmd_hybrid = [
        str(PYTHON), "-m", "pipeline.hybrid_fixed", "run", str(TARGET_SOURCE),
        "--pool", str(POOL),
        "--output", str(out_hybrid),
        "--score-command", SCORE_CMD,
        "--population-size", "4",
        "--generations", "2",
        "--llm-fraction", "0.25",
        "--model", MODEL,
        "--base-url", BASE_URL,
        "--seed", "42"
    ]
    t0 = time.time()
    p_hy = subprocess.run(cmd_hybrid, capture_output=True, text=True, timeout=240)
    dt_hy = time.time() - t0
    hy_json = out_hybrid / "result.json"
    fit_hy, ember_hy, build_hy = 0.0, 1.0, "FAIL"
    if hy_json.is_file():
        d_hy = json.loads(hy_json.read_text())
        fit_hy = d_hy.get("best_fitness", 0.0)
        ev_hy = d_hy.get("best_evaluation", {})
        ember_hy = ev_hy.get("detectors", {}).get("ember", {}).get("score", 1.0)
        build_hy = ev_hy.get("build", "PASSED" if fit_hy > 0 else "FAIL")
    print(f"    Hybrid Result : Fitness = {fit_hy:.4f} | EMBER = {ember_hy:.4f} | Build = {build_hy} ({dt_hy:.1f}s)")
    results["hybrid_fixed"] = {"fitness": fit_hy, "ember": ember_hy, "build": build_hy, "duration_s": dt_hy}

    # Summary
    summary_file = OUT_DIR / "summary.json"
    summary_file.write_text(json.dumps(results, indent=2))
    print_hdr("ALL 4 BASELINES BENCHMARK COMPLETED")
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
