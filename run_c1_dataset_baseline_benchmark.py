#!/usr/bin/env python3
"""
Benchmark selected Baselines on C1 Dataset with Behavior Verifier enabled.
Targets 3 representative samples:
  1. g1_01_local_thread (Process Injection)
  2. g3_02_hash_djb2 (API Hook Evasion)
  3. g4_01_peb_debugger (Anti-Analysis)
"""

import sys
import json
import time
import subprocess
from pathlib import Path

ROOT = Path("/home/dangnosuy/Documents/UIT/KLTN")
PYTHON = Path.home() / "Documents/venv/bin/python3"
SCORE_CMD = f"{PYTHON} -m pipeline.ga_only.static_score {{source}} --engines clamav,ember,malconv"
OUT_DIR = ROOT / "baseline_results/c1_dataset_run"
OUT_DIR.mkdir(parents=True, exist_ok=True)

TARGETS = [
    {
        "id": "g1_01_local_thread",
        "path": ROOT / "sources/dataset/g1_process_injection/g1_01_local_thread.c",
        "technique": "Local Thread RWX Injection"
    },
    {
        "id": "g3_02_hash_djb2",
        "path": ROOT / "sources/dataset/g3_api_hook_evasion/g3_02_hash_djb2.c",
        "technique": "PEB Walk & DJB2 API Hashing"
    },
    {
        "id": "g4_01_peb_debugger",
        "path": ROOT / "sources/dataset/g4_anti_analysis/g4_01_peb_debugger.c",
        "technique": "PEB BeingDebugged Anti-Analysis"
    }
]

def score_file(source: Path) -> dict:
    cmd = [str(PYTHON), "-m", "pipeline.ga_only.static_score", str(source), "--engines", "clamav,ember,malconv"]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if p.returncode == 0:
        return json.loads(p.stdout)
    return {"fitness": 0.0, "build": "FAIL", "error": p.stderr.strip()[:200]}

def run():
    print("=" * 70)
    print(" C1 DATASET + BEHAVIOR VERIFIER BASELINE BENCHMARK")
    print("=" * 70)

    summary = {}

    for t in TARGETS:
        sid = t["id"]
        src = t["path"]
        print(f"\n[*] Evaluating Target: {sid} ({t['technique']})")

        # 1. Ground Truth Original
        orig_res = score_file(src)
        ember_orig = orig_res.get("detectors", {}).get("ember", {}).get("score", 1.0)
        fit_orig = orig_res.get("fitness", 0.0)
        print(f"    - Original Ground Truth : Fitness = {fit_orig:.4f} | EMBER = {ember_orig:.4f} | Build = {orig_res.get('build')}")

        # 2. Baseline: Heuristic / Deterministic Mutation Chain
        heur_out = OUT_DIR / "heuristic" / sid
        heur_out.mkdir(parents=True, exist_ok=True)
        heur_cmd = [
            str(PYTHON), "-m", "pipeline.heuristic", "run", str(src),
            "--pool", str(ROOT / "pipeline/mutators/native_pool.json"),
            "--recipe", str(ROOT / "pipeline/heuristic/native_recipe.json"),
            "--output", str(heur_out),
            "--score-command", SCORE_CMD
        ]
        t0 = time.time()
        p_heur = subprocess.run(heur_cmd, capture_output=True, text=True, timeout=180)
        dur_heur = time.time() - t0
        heur_json = heur_out / "result.json"
        heur_fit = 0.0
        heur_ember = 1.0
        heur_build = "FAIL"
        if heur_json.is_file():
            h_data = json.loads(heur_json.read_text())
            heur_fit = h_data.get("fitness", 0.0)
            ev = h_data.get("evaluation", {})
            heur_build = ev.get("build", "FAIL")
            heur_ember = ev.get("detectors", {}).get("ember", {}).get("score", 1.0)
        print(f"    - Baseline Heuristic     : Fitness = {heur_fit:.4f} | EMBER = {heur_ember:.4f} | Build = {heur_build} ({dur_heur:.1f}s)")

        # 3. Baseline: Multi-Armed Bandit (MAB)
        bandit_out = OUT_DIR / "bandit" / sid
        bandit_out.mkdir(parents=True, exist_ok=True)
        bandit_cmd = [
            str(PYTHON), "-m", "pipeline.bandit", "run", str(src),
            "--pool", str(ROOT / "pipeline/mutators/native_pool.json"),
            "--output", str(bandit_out),
            "--score-command", SCORE_CMD,
            "--budget", "2",
            "--seed", "42"
        ]
        t0 = time.time()
        p_bandit = subprocess.run(bandit_cmd, capture_output=True, text=True, timeout=180)
        dur_bandit = time.time() - t0
        bandit_json = bandit_out / "result.json"
        bandit_fit = 0.0
        bandit_ember = 1.0
        bandit_build = "FAIL"
        if bandit_json.is_file():
            b_data = json.loads(bandit_json.read_text())
            bandit_fit = b_data.get("best_fitness", 0.0)
            bandit_build = "PASSED" if bandit_fit > 0 else "FAIL"
            # Extract from best evaluation
            ev = b_data.get("best_evaluation", {})
            bandit_ember = ev.get("detectors", {}).get("ember", {}).get("score", 1.0)
        print(f"    - Baseline Bandit (MAB)  : Fitness = {bandit_fit:.4f} | EMBER = {bandit_ember:.4f} | Build = {bandit_build} ({dur_bandit:.1f}s)")

        # 4. Baseline: GA Only
        ga_out = OUT_DIR / "ga_only" / sid
        ga_out.mkdir(parents=True, exist_ok=True)
        ga_cmd = [
            str(PYTHON), "-m", "pipeline.ga_only", "run", str(src),
            "--pool", str(ROOT / "pipeline/mutators/native_pool.json"),
            "--output", str(ga_out),
            "--score-command", SCORE_CMD,
            "--population-size", "4",
            "--generations", "2",
            "--seed", "42"
        ]
        t0 = time.time()
        p_ga = subprocess.run(ga_cmd, capture_output=True, text=True, timeout=180)
        dur_ga = time.time() - t0
        ga_json = ga_out / "result.json"
        ga_fit = 0.0
        ga_ember = 1.0
        ga_build = "FAIL"
        if ga_json.is_file():
            g_data = json.loads(ga_json.read_text())
            ga_fit = g_data.get("best_fitness", 0.0)
            ev = g_data.get("best_evaluation", {})
            ga_build = ev.get("build", "FAIL")
            ga_ember = ev.get("detectors", {}).get("ember", {}).get("score", 1.0)
        print(f"    - Baseline GA-Only       : Fitness = {ga_fit:.4f} | EMBER = {ga_ember:.4f} | Build = {ga_build} ({dur_ga:.1f}s)")

        summary[sid] = {
            "technique": t["technique"],
            "original": {"fitness": fit_orig, "ember": ember_orig, "build": orig_res.get("build")},
            "heuristic": {"fitness": heur_fit, "ember": heur_ember, "build": heur_build},
            "bandit": {"fitness": bandit_fit, "ember": bandit_ember, "build": bandit_build},
            "ga_only": {"fitness": ga_fit, "ember": ga_ember, "build": ga_build}
        }

    summary_file = OUT_DIR / "c1_baseline_benchmark_summary.json"
    summary_file.write_text(json.dumps(summary, indent=2))
    print("\n" + "=" * 70)
    print(f" Done! Summary saved to {summary_file}")
    print("=" * 70)

if __name__ == "__main__":
    run()
