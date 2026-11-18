#!/usr/bin/env python3
"""Run baselines with 4-engine detector suite (clamav, ember, malconv, cape) on 3 sample types."""

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
RESULTS_DIR = ROOT / "baseline_results/detectors_3types"
POOL = ROOT / "pipeline/mutators/native_pool.json"
RECIPE = ROOT / "pipeline/heuristic/native_recipe.json"
SCORE_CMD = f"{PYTHON} -m pipeline.ga_only.static_score {{source}} --engines clamav,ember,malconv,cape"

SAMPLES = [
    {
        "type": "Thường (Basic)",
        "source": ROOT / "dataset/advanced/sources/baseline/local_exec_xor.c",
        "tag": "local_exec_xor",
    },
    {
        "type": "Nâng cao (Advanced)",
        "source": ROOT / "dataset/advanced/sources/baseline/unhook_exec_xor.c",
        "tag": "unhook_exec_xor",
    },
    {
        "type": "Có DLL kèm (Companion)",
        "source": ROOT / "dataset/advanced/sources/injection/classic_dll_injection.c",
        "tag": "classic_dll_injection",
    },
]


def run_cmd(cmd: list[str], timeout: int = 300) -> tuple[int, str, str]:
    t0 = time.time()
    try:
        p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"Timeout after {timeout}s"
    except Exception as e:
        return 1, "", str(e)


def run_original(sample_info: dict) -> dict:
    source = sample_info["source"]
    tag = sample_info["tag"]
    print(f"\n[Original] Scoring ground truth: {tag} ...", flush=True)
    out_dir = RESULTS_DIR / "original" / tag
    res_file = out_dir / "result.json"
    if res_file.is_file():
        res = json.loads(res_file.read_text())
        print(f"  {tag:<25}: fitness={res.get('fitness', 0.0):.4f} (cached)")
        return res

    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [str(PYTHON), "-m", "pipeline.ga_only.static_score", str(source), "--engines", "clamav,ember,malconv,cape"]
    code, stdout, stderr = run_cmd(cmd, timeout=240)
    if code == 0:
        res = json.loads(stdout)
        res_file.write_text(json.dumps(res, indent=2))
        print(f"  {tag:<25}: fitness={res.get('fitness', 0.0):.4f}, cape={res.get('detectors',{}).get('cape',{}).get('score')}")
        return res
    else:
        print(f"  {tag:<25}: FAILED {stderr[-150:]}")
        return {"fitness": 0.0, "error": stderr}


def run_heuristic(sample_info: dict) -> dict:
    source = sample_info["source"]
    tag = sample_info["tag"]
    print(f"\n[Heuristic] Running deterministic chain: {tag} ...", flush=True)
    out_dir = RESULTS_DIR / "heuristic" / tag
    res_file = out_dir / "result.json"
    if res_file.is_file():
        res = json.loads(res_file.read_text())
        print(f"  {tag:<25}: fitness={res.get('fitness', 0.0):.4f} (cached)")
        return res

    cmd = [
        str(PYTHON), "-m", "pipeline.heuristic", "run", str(source),
        "--pool", str(POOL),
        "--recipe", str(RECIPE),
        "--output", str(out_dir),
        "--score-command", SCORE_CMD,
    ]
    code, stdout, stderr = run_cmd(cmd, timeout=240)
    if res_file.is_file():
        res = json.loads(res_file.read_text())
        ev = res.get("evaluation", {})
        print(f"  {tag:<25}: fitness={res.get('fitness', 0.0):.4f}, cape={ev.get('detectors',{}).get('cape',{}).get('score')}")
        return res
    else:
        print(f"  {tag:<25}: FAILED {stderr[-150:]}")
        return {"fitness": 0.0, "error": stderr}


def run_bandit(sample_info: dict) -> dict:
    source = sample_info["source"]
    tag = sample_info["tag"]
    print(f"\n[Bandit] Running MAB (budget=2): {tag} ...", flush=True)
    out_dir = RESULTS_DIR / "bandit" / tag
    res_file = out_dir / "result.json"
    if res_file.is_file():
        res = json.loads(res_file.read_text())
        print(f"  {tag:<25}: fitness={res.get('best_fitness', 0.0):.4f} (cached)")
        return res

    cmd = [
        str(PYTHON), "-m", "pipeline.bandit", "run", str(source),
        "--pool", str(POOL),
        "--output", str(out_dir),
        "--score-command", SCORE_CMD,
        "--budget", "2",
        "--max-actions", "1",
        "--seed", "42",
    ]
    code, stdout, stderr = run_cmd(cmd, timeout=360)
    if res_file.is_file():
        res = json.loads(res_file.read_text())
        print(f"  {tag:<25}: fitness={res.get('best_fitness', 0.0):.4f}, genes={res.get('best_genes')}")
        return res
    else:
        print(f"  {tag:<25}: FAILED {stderr[-150:]}")
        return {"best_fitness": 0.0, "error": stderr}


def run_xprimes(sample_info: dict) -> dict:
    source = sample_info["source"]
    tag = sample_info["tag"]
    print(f"\n[xPriMES] Running Dual-Env RL (budget=2): {tag} ...", flush=True)
    out_dir = RESULTS_DIR / "xprimes" / tag
    res_file = out_dir / "result.json"
    if res_file.is_file():
        res = json.loads(res_file.read_text())
        print(f"  {tag:<25}: fitness={res.get('best_fitness', 0.0):.4f} (cached)")
        return res

    cmd = [
        str(PYTHON), "-m", "pipeline.xprimes", "run", str(source),
        "--pool", str(POOL),
        "--output", str(out_dir),
        "--target", "ember",
        "--score-command", SCORE_CMD,
        "--budget", "2",
        "--seed", "42",
    ]
    code, stdout, stderr = run_cmd(cmd, timeout=360)
    if res_file.is_file():
        res = json.loads(res_file.read_text())
        print(f"  {tag:<25}: fitness={res.get('best_fitness', 0.0):.4f}, genes={res.get('best_genes')}")
        return res
    else:
        print(f"  {tag:<25}: FAILED {stderr[-150:]}")
        return {"best_fitness": 0.0, "error": stderr}


def run_proposed(sample_info: dict) -> dict:
    source = sample_info["source"]
    tag = sample_info["tag"]
    print(f"\n[Proposed] Running C2 + NSGA-II (evals=2): {tag} ...", flush=True)
    out_dir = RESULTS_DIR / "proposed" / tag
    res_file = out_dir / "result.json"
    if res_file.is_file():
        res = json.loads(res_file.read_text())
        print(f"  {tag:<25}: fitness={res.get('best_fitness', 0.0):.4f} (cached)")
        return res

    cmd = [
        str(PYTHON), "-m", "pipeline.proposed", "run", str(source),
        "--pool", str(POOL),
        "--output", str(out_dir),
        "--score-command", SCORE_CMD,
        "--population-size", "2",
        "--generations", "1",
        "--chromosome-length", "1",
        "--stagnation-patience", "1",
        "--max-llm-calls", "0",
        "--no-llm",
        "--seed", "42",
    ]
    code, stdout, stderr = run_cmd(cmd, timeout=360)
    if res_file.is_file():
        res = json.loads(res_file.read_text())
        print(f"  {tag:<25}: fitness={res.get('best_fitness', 0.0):.4f}, genes={res.get('best_genes')}")
        return res
    else:
        print(f"  {tag:<25}: FAILED {stderr[-150:]}")
        return {"best_fitness": 0.0, "error": stderr}


def main():
    print("=================================================================")
    print("  Benchmark 3 Sample Types with 4-Engine Detector Suite")
    print("  Engines: ClamAV, EMBER, MalConv, CAPE Sandbox")
    print("=================================================================")
    t_start = time.time()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    all_results = {
        "original": {},
        "heuristic": {},
        "bandit": {},
        "xprimes": {},
        "proposed": {},
    }

    for s in SAMPLES:
        all_results["original"][s["tag"]] = run_original(s)
        all_results["heuristic"][s["tag"]] = run_heuristic(s)
        all_results["bandit"][s["tag"]] = run_bandit(s)
        all_results["xprimes"][s["tag"]] = run_xprimes(s)
        all_results["proposed"][s["tag"]] = run_proposed(s)

    out_file = RESULTS_DIR / "benchmark_summary.json"
    out_file.write_text(json.dumps(all_results, indent=2))
    print(f"\nAll benchmark runs completed in {round(time.time() - t_start, 1)}s.")
    print(f"Summary saved to: {out_file}")


if __name__ == "__main__":
    main()
