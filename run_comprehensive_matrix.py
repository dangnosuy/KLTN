#!/usr/bin/env python3
"""
Comprehensive Benchmark: Baselines vs Proposed Method on C1 Dataset with Behavior Verifier.
Samples evaluated across MITRE groups:
  1. g3_02_hash_djb2 (TA0005 Defense Evasion / API Hook Evasion)
  2. g4_01_peb_debugger (TA0005 Defense Evasion / Anti-Analysis)
  3. g7_01_file_crud (Benign System Control / File CRUD)

Methods evaluated:
  - Original Ground Truth
  - Multi-Armed Bandit (MAB Thompson Sampling)
  - Genetic Algorithm (GA-Only)
  - Fixed Hybrid (EoH GA + LLM)
  - Proposed Method (C2 Coordinator + NSGA-II Multi-Objective + Qwen 3.8-27b Reflexion)
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
BASE_OUT = ROOT / "baseline_results/comprehensive_matrix"
BASE_OUT.mkdir(parents=True, exist_ok=True)

MODEL = "cf/@cf/qwen/qwen3.8-27b"
BASE_URL = "http://127.0.0.1:20128/v1"

SAMPLES = [
    {
        "id": "g3_02_hash_djb2",
        "path": ROOT / "sources/dataset/g3_api_hook_evasion/g3_02_hash_djb2.c",
        "group": "g3_api_hook_evasion",
        "technique": "PEB Walk & DJB2 API Hash Resolution"
    },
    {
        "id": "g4_01_peb_debugger",
        "path": ROOT / "sources/dataset/g4_anti_analysis/g4_01_peb_debugger.c",
        "group": "g4_anti_analysis",
        "technique": "PEB BeingDebugged Anti-Analysis"
    },
    {
        "id": "g7_01_file_crud",
        "path": ROOT / "sources/dataset/g7_benign_controls/g7_01_file_crud.c",
        "group": "g7_benign_controls",
        "technique": "Benign System File CRUD Control"
    }
]

def score_source(src: Path) -> dict:
    cmd = [str(PYTHON), "-m", "pipeline.ga_only.static_score", str(src), "--engines", "clamav,ember,malconv"]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if p.returncode == 0:
        return json.loads(p.stdout)
    return {"fitness": 0.0, "build": "FAIL", "error": p.stderr.strip()[:200]}

def run():
    print("=" * 80)
    print(" COMPREHENSIVE BENCHMARK: BASELINES VS PROPOSED METHOD (C1 DATASET + VERIFIER)")
    print("=" * 80)

    matrix = {}

    for s in SAMPLES:
        sid = s["id"]
        src = s["path"]
        print(f"\n=======================================================")
        print(f"[*] Target: {sid} ({s['technique']})")
        print(f"=======================================================")

        s_res = {"technique": s["technique"], "group": s["group"]}

        # 0. Original
        orig_ev = score_source(src)
        fit_0 = orig_ev.get("fitness", 0.0)
        emb_0 = orig_ev.get("detectors", {}).get("ember", {}).get("score", 1.0)
        build_0 = orig_ev.get("build", "FAIL")
        print(f"  [Original]   Fitness = {fit_0:.4f} | EMBER = {emb_0:.4f} | Verifier = {build_0}")
        s_res["original"] = {"fitness": fit_0, "ember": emb_0, "build": build_0}

        # 1. Multi-Armed Bandit (MAB)
        out_b = BASE_OUT / sid / "bandit"
        if not (out_b / "result.json").is_file():
            out_b.mkdir(parents=True, exist_ok=True)
            cmd_b = [
                str(PYTHON), "-m", "pipeline.bandit", "run", str(src),
                "--pool", str(POOL), "--output", str(out_b),
                "--score-command", SCORE_CMD, "--budget", "4", "--seed", "42"
            ]
            subprocess.run(cmd_b, capture_output=True, text=True, timeout=180)
        fit_b, emb_b, build_b = 0.0, 1.0, "FAIL"
        if (out_b / "result.json").is_file():
            d_b = json.loads((out_b / "result.json").read_text())
            fit_b = d_b.get("best_fitness", 0.0)
            ev_b = d_b.get("best_evaluation", {})
            emb_b = ev_b.get("detectors", {}).get("ember", {}).get("score", 1.0)
            build_b = ev_b.get("build", "PASSED" if fit_b > 0 else "FAIL")
        print(f"  [Bandit]     Fitness = {fit_b:.4f} | EMBER = {emb_b:.4f} | Verifier = {build_b}")
        s_res["bandit"] = {"fitness": fit_b, "ember": emb_b, "build": build_b}

        # 2. GA-Only
        out_ga = BASE_OUT / sid / "ga_only"
        if not (out_ga / "result.json").is_file():
            out_ga.mkdir(parents=True, exist_ok=True)
            cmd_ga = [
                str(PYTHON), "-m", "pipeline.ga_only", "run", str(src),
                "--pool", str(POOL), "--output", str(out_ga),
                "--score-command", SCORE_CMD, "--population-size", "4",
                "--generations", "2", "--seed", "42"
            ]
            subprocess.run(cmd_ga, capture_output=True, text=True, timeout=180)
        fit_ga, emb_ga, build_ga = 0.0, 1.0, "FAIL"
        if (out_ga / "result.json").is_file():
            d_ga = json.loads((out_ga / "result.json").read_text())
            fit_ga = d_ga.get("best_fitness", 0.0)
            ev_ga = d_ga.get("best_evaluation", {})
            emb_ga = ev_ga.get("detectors", {}).get("ember", {}).get("score", 1.0)
            build_ga = ev_ga.get("build", "PASSED" if fit_ga > 0 else "FAIL")
        print(f"  [GA-Only]    Fitness = {fit_ga:.4f} | EMBER = {emb_ga:.4f} | Verifier = {build_ga}")
        s_res["ga_only"] = {"fitness": fit_ga, "ember": emb_ga, "build": build_ga}

        # 3. Fixed Hybrid (GA + LLM)
        out_hy = BASE_OUT / sid / "hybrid_fixed"
        if not (out_hy / "result.json").is_file():
            out_hy.mkdir(parents=True, exist_ok=True)
            cmd_hy = [
                str(PYTHON), "-m", "pipeline.hybrid_fixed", "run", str(src),
                "--pool", str(POOL), "--output", str(out_hy),
                "--score-command", SCORE_CMD, "--population-size", "2",
                "--generations", "1", "--max-evaluations", "2", "--llm-fraction", "0.5",
                "--model", MODEL, "--base-url", BASE_URL, "--seed", "42"
            ]
            subprocess.run(cmd_hy, capture_output=True, text=True, timeout=180)
        fit_hy, emb_hy, build_hy = 0.0, 1.0, "FAIL"
        if (out_hy / "result.json").is_file():
            d_hy = json.loads((out_hy / "result.json").read_text())
            fit_hy = d_hy.get("best_fitness", 0.0)
            ev_hy = d_hy.get("best_evaluation", {})
            emb_hy = ev_hy.get("detectors", {}).get("ember", {}).get("score", 1.0)
            build_hy = ev_hy.get("build", "PASSED" if fit_hy > 0 else "FAIL")
        print(f"  [Hybrid]     Fitness = {fit_hy:.4f} | EMBER = {emb_hy:.4f} | Verifier = {build_hy}")
        s_res["hybrid_fixed"] = {"fitness": fit_hy, "ember": emb_hy, "build": build_hy}

        # 4. Proposed Method (C2 + NSGA-II + Qwen 3.8-27b Reflexion)
        out_prop = BASE_OUT / sid / "proposed"
        if not (out_prop / "result.json").is_file():
            out_prop.mkdir(parents=True, exist_ok=True)
            cmd_prop = [
                str(PYTHON), "-m", "pipeline.proposed", "run", str(src),
                "--pool", str(POOL), "--output", str(out_prop),
                "--score-command", SCORE_CMD, "--population-size", "4",
                "--generations", "2", "--chromosome-length", "3",
                "--stagnation-patience", "1", "--max-llm-calls", "1",
                "--max-evaluations", "8", "--model", MODEL,
                "--base-url", BASE_URL, "--seed", "42"
            ]
            subprocess.run(cmd_prop, capture_output=True, text=True, timeout=240)
        fit_prop, emb_prop, build_prop = 0.0, 1.0, "FAIL"
        if (out_prop / "result.json").is_file():
            d_p = json.loads((out_prop / "result.json").read_text())
            fit_prop = d_p.get("best_fitness", 0.0)
            # score best.c directly to obtain detector breakdown
            best_c = out_prop / "best.c"
            if best_c.is_file():
                ev_p = score_source(best_c)
                emb_prop = ev_p.get("detectors", {}).get("ember", {}).get("score", 1.0)
                build_prop = ev_p.get("build", "PASSED" if fit_prop > 0 else "FAIL")
            else:
                build_prop = "PASSED" if fit_prop > 0 else "FAIL"
        print(f"  [Proposed]   Fitness = {fit_prop:.4f} | EMBER = {emb_prop:.4f} | Verifier = {build_prop}")
        s_res["proposed"] = {"fitness": fit_prop, "ember": emb_prop, "build": build_prop}

        matrix[sid] = s_res

    out_file = BASE_OUT / "comprehensive_summary.json"
    out_file.write_text(json.dumps(matrix, indent=2))
    print("\n" + "=" * 80)
    print(f" Done! Comprehensive matrix saved to {out_file}")
    print("=" * 80)

if __name__ == "__main__":
    run()
