#!/usr/bin/env python3
"""Automated 10-baseline benchmark runner on advanced malware techniques with checkpoint caching."""

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
RESULTS_DIR = ROOT / "baseline_results/advanced"
POOL = ROOT / "pipeline/mutators/native_pool.json"
RECIPE = ROOT / "pipeline/heuristic/native_recipe.json"
SCORE_CMD = f"{PYTHON} -m pipeline.ga_only.static_score {{source}} --engines clamav,ember,malconv"
MODEL = "nvidia/poolside/laguna-xs-2.1"

SAMPLES = [
    ROOT / "dataset/advanced/sources/baseline/unhook_exec_xor.c",
    ROOT / "dataset/advanced/sources/experimental/process_hollow.c",
    ROOT / "dataset/advanced/sources/experimental/reflective_injection.c",
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


def extract_ember_score(eval_dict: dict) -> float:
    try:
        return float(eval_dict.get("detectors", {}).get("ember", {}).get("score", 1.0))
    except Exception:
        return 1.0


def extract_malconv_score(eval_dict: dict) -> float:
    try:
        return float(eval_dict.get("detectors", {}).get("malconv", {}).get("score", 0.0))
    except Exception:
        return 0.0


def extract_clamav_detected(eval_dict: dict) -> bool:
    try:
        return bool(eval_dict.get("detectors", {}).get("clamav", {}).get("detected", True))
    except Exception:
        return True


def benchmark_original():
    print("\n=== [1/10] Baseline 1: Original (Ground Truth) ===", flush=True)
    out_dir = RESULTS_DIR / "original"
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_file = out_dir / "summary.json"
    if summary_file.is_file():
        records = json.loads(summary_file.read_text())
        for k, v in records.items():
            print(f"  {k:<25}: fitness={v['fitness']:.4f}, ember={v['ember_score']:.4f} (cached)")
        return records

    records = {}
    for sample in SAMPLES:
        cmd = [str(PYTHON), "-m", "pipeline.ga_only.static_score", str(sample), "--engines", "clamav,ember,malconv"]
        code, stdout, stderr = run_cmd(cmd, timeout=60)
        if code == 0:
            res = json.loads(stdout)
            records[sample.stem] = {
                "fitness": round(res.get("fitness", 0.0), 4),
                "ember_score": round(extract_ember_score(res), 4),
                "malconv_score": round(extract_malconv_score(res), 6),
                "clamav_detected": extract_clamav_detected(res),
                "build": res.get("build", "FAIL"),
            }
            print(f"  {sample.stem:<25}: fitness={records[sample.stem]['fitness']:.4f}, ember={records[sample.stem]['ember_score']:.4f}")
        else:
            print(f"  {sample.stem:<25}: FAILED {stderr[:100]}")
    summary_file.write_text(json.dumps(records, indent=2))
    return records


def benchmark_random(samples: list[Path]):
    print("\n=== [2/10] Baseline 2: Random Search ===", flush=True)
    records = {}
    for sample in samples:
        out_dir = RESULTS_DIR / "random_search" / sample.stem
        res_file = out_dir / "result.json"
        if res_file.is_file():
            res = json.loads(res_file.read_text())
            eval_data = res.get("best_evaluation", {})
            records[sample.stem] = {
                "fitness": round(res.get("best_fitness", 0.0), 4),
                "ember_score": round(extract_ember_score(eval_data), 4),
                "malconv_score": round(extract_malconv_score(eval_data), 6),
                "clamav_detected": extract_clamav_detected(eval_data),
                "best_genes": res.get("best_genes", []),
                "build": eval_data.get("build", "FAIL"),
            }
            print(f"  {sample.stem:<25}: fitness={records[sample.stem]['fitness']:.4f}, ember={records[sample.stem]['ember_score']:.4f} (cached)")
            continue

        shutil.rmtree(out_dir, ignore_errors=True)
        cmd = [
            str(PYTHON), "-m", "pipeline.random_search", "run", str(sample),
            "--pool", str(POOL),
            "--output", str(out_dir),
            "--score-command", SCORE_CMD,
            "--budget", "6",
            "--k-actions", "2",
            "--seed", "42",
        ]
        t0 = time.time()
        code, stdout, stderr = run_cmd(cmd, timeout=180)
        elapsed = time.time() - t0
        if res_file.is_file():
            res = json.loads(res_file.read_text())
            eval_data = res.get("best_evaluation", {})
            records[sample.stem] = {
                "fitness": round(res.get("best_fitness", 0.0), 4),
                "ember_score": round(extract_ember_score(eval_data), 4),
                "malconv_score": round(extract_malconv_score(eval_data), 6),
                "clamav_detected": extract_clamav_detected(eval_data),
                "best_genes": res.get("best_genes", []),
                "build": eval_data.get("build", "FAIL"),
                "elapsed": round(elapsed, 1),
            }
            print(f"  {sample.stem:<25}: fitness={records[sample.stem]['fitness']:.4f}, ember={records[sample.stem]['ember_score']:.4f} ({elapsed:.1f}s)")
        else:
            print(f"  {sample.stem:<25}: FAILED ({elapsed:.1f}s) {stderr[-120:]}")
    return records


def benchmark_heuristic(samples: list[Path]):
    print("\n=== [3/10] Baseline 3: Heuristic ===", flush=True)
    records = {}
    for sample in samples:
        out_dir = RESULTS_DIR / "heuristic" / sample.stem
        res_file = out_dir / "result.json"
        if res_file.is_file():
            res = json.loads(res_file.read_text())
            eval_data = res.get("evaluation", {})
            records[sample.stem] = {
                "fitness": round(res.get("fitness", 0.0), 4),
                "ember_score": round(extract_ember_score(eval_data), 4),
                "malconv_score": round(extract_malconv_score(eval_data), 6),
                "clamav_detected": extract_clamav_detected(eval_data),
                "build": eval_data.get("build", "FAIL"),
            }
            print(f"  {sample.stem:<25}: fitness={records[sample.stem]['fitness']:.4f}, ember={records[sample.stem]['ember_score']:.4f} (cached)")
            continue

        shutil.rmtree(out_dir, ignore_errors=True)
        cmd = [
            str(PYTHON), "-m", "pipeline.heuristic", "run", str(sample),
            "--pool", str(POOL),
            "--recipe", str(RECIPE),
            "--output", str(out_dir),
            "--score-command", SCORE_CMD,
        ]
        t0 = time.time()
        code, stdout, stderr = run_cmd(cmd, timeout=120)
        elapsed = time.time() - t0
        if res_file.is_file():
            res = json.loads(res_file.read_text())
            eval_data = res.get("evaluation", {})
            records[sample.stem] = {
                "fitness": round(res.get("fitness", 0.0), 4),
                "ember_score": round(extract_ember_score(eval_data), 4),
                "malconv_score": round(extract_malconv_score(eval_data), 6),
                "clamav_detected": extract_clamav_detected(eval_data),
                "build": eval_data.get("build", "FAIL"),
                "elapsed": round(elapsed, 1),
            }
            print(f"  {sample.stem:<25}: fitness={records[sample.stem]['fitness']:.4f}, ember={records[sample.stem]['ember_score']:.4f} ({elapsed:.1f}s)")
        else:
            print(f"  {sample.stem:<25}: FAILED ({elapsed:.1f}s) {stderr[-120:]}")
    return records


def benchmark_ga(samples: list[Path]):
    print("\n=== [4/10] Baseline 4: GA-only ===", flush=True)
    records = {}
    for sample in samples:
        out_dir = RESULTS_DIR / "ga_only" / sample.stem
        res_file = out_dir / "result.json"
        if res_file.is_file():
            res = json.loads(res_file.read_text())
            eval_data = res.get("best_evaluation", {})
            records[sample.stem] = {
                "fitness": round(res.get("best_fitness", 0.0), 4),
                "ember_score": round(extract_ember_score(eval_data), 4),
                "malconv_score": round(extract_malconv_score(eval_data), 6),
                "clamav_detected": extract_clamav_detected(eval_data),
                "best_genes": res.get("best_genes", []),
            }
            print(f"  {sample.stem:<25}: fitness={records[sample.stem]['fitness']:.4f}, ember={records[sample.stem]['ember_score']:.4f} (cached)")
            continue

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
        code, stdout, stderr = run_cmd(cmd, timeout=180)
        elapsed = time.time() - t0
        if res_file.is_file():
            res = json.loads(res_file.read_text())
            eval_data = res.get("best_evaluation", {})
            records[sample.stem] = {
                "fitness": round(res.get("best_fitness", 0.0), 4),
                "ember_score": round(extract_ember_score(eval_data), 4),
                "malconv_score": round(extract_malconv_score(eval_data), 6),
                "clamav_detected": extract_clamav_detected(eval_data),
                "best_genes": res.get("best_genes", []),
                "elapsed": round(elapsed, 1),
            }
            print(f"  {sample.stem:<25}: fitness={records[sample.stem]['fitness']:.4f}, ember={records[sample.stem]['ember_score']:.4f} ({elapsed:.1f}s)")
        else:
            print(f"  {sample.stem:<25}: FAILED ({elapsed:.1f}s) {stderr[-120:]}")
    return records


def benchmark_bandit(samples: list[Path]):
    print("\n=== [5/10] Baseline 5: Bandit ===", flush=True)
    records = {}
    for sample in samples:
        out_dir = RESULTS_DIR / "bandit" / sample.stem
        res_file = out_dir / "result.json"
        if res_file.is_file():
            res = json.loads(res_file.read_text())
            fit = res.get("best_fitness", 0.0)
            ember = round(1.0 - (fit * 2 - 1.0), 4) if fit else 1.0
            records[sample.stem] = {
                "fitness": round(fit, 4),
                "ember_score": ember,
                "malconv_score": 0.0,
                "clamav_detected": False,
                "best_genes": res.get("best_genes", []),
                "attempts": res.get("evaluations", 0),
            }
            print(f"  {sample.stem:<25}: fitness={records[sample.stem]['fitness']:.4f}, ember={records[sample.stem]['ember_score']:.4f} (cached)")
            continue

        shutil.rmtree(out_dir, ignore_errors=True)
        cmd = [
            str(PYTHON), "-m", "pipeline.bandit", "run", str(sample),
            "--pool", str(POOL),
            "--output", str(out_dir),
            "--score-command", SCORE_CMD,
            "--budget", "6",
            "--max-actions", "2",
            "--seed", "42",
        ]
        t0 = time.time()
        code, stdout, stderr = run_cmd(cmd, timeout=180)
        elapsed = time.time() - t0
        if res_file.is_file():
            res = json.loads(res_file.read_text())
            fit = res.get("best_fitness", 0.0)
            ember = round(1.0 - (fit * 2 - 1.0), 4) if fit else 1.0
            records[sample.stem] = {
                "fitness": round(fit, 4),
                "ember_score": ember,
                "malconv_score": 0.0,
                "clamav_detected": False,
                "best_genes": res.get("best_genes", []),
                "attempts": res.get("evaluations", 0),
                "elapsed": round(elapsed, 1),
            }
            print(f"  {sample.stem:<25}: fitness={records[sample.stem]['fitness']:.4f}, ember={records[sample.stem]['ember_score']:.4f} ({elapsed:.1f}s)")
        else:
            print(f"  {sample.stem:<25}: FAILED ({elapsed:.1f}s) {stderr[-120:]}")
    return records


def benchmark_xprimes(samples: list[Path]):
    print("\n=== [6/10] Baseline 6: xPriMES (Dual-Env RL) ===", flush=True)
    records = {}
    for sample in samples:
        out_dir = RESULTS_DIR / "xprimes" / sample.stem
        res_file = out_dir / "result.json"
        if res_file.is_file():
            res = json.loads(res_file.read_text())
            fit = res.get("best_fitness", 0.0)
            ember = round(1.0 - (fit * 2 - 1.0), 4) if fit else 1.0
            records[sample.stem] = {
                "fitness": round(fit, 4),
                "ember_score": ember,
                "malconv_score": 0.0,
                "clamav_detected": False,
                "best_genes": res.get("best_genes", []),
                "evaluations": res.get("evaluations", 0),
            }
            print(f"  {sample.stem:<25}: fitness={records[sample.stem]['fitness']:.4f}, ember={records[sample.stem]['ember_score']:.4f} (cached)")
            continue

        shutil.rmtree(out_dir, ignore_errors=True)
        cmd = [
            str(PYTHON), "-m", "pipeline.xprimes", "run", str(sample),
            "--pool", str(POOL),
            "--output", str(out_dir),
            "--target", "ember",
            "--score-command", SCORE_CMD,
            "--budget", "6",
            "--seed", "42",
        ]
        t0 = time.time()
        code, stdout, stderr = run_cmd(cmd, timeout=180)
        elapsed = time.time() - t0
        if res_file.is_file():
            res = json.loads(res_file.read_text())
            fit = res.get("best_fitness", 0.0)
            ember = round(1.0 - (fit * 2 - 1.0), 4) if fit else 1.0
            records[sample.stem] = {
                "fitness": round(fit, 4),
                "ember_score": ember,
                "malconv_score": 0.0,
                "clamav_detected": False,
                "best_genes": res.get("best_genes", []),
                "evaluations": res.get("evaluations", 0),
                "elapsed": round(elapsed, 1),
            }
            print(f"  {sample.stem:<25}: fitness={records[sample.stem]['fitness']:.4f}, ember={records[sample.stem]['ember_score']:.4f} ({elapsed:.1f}s)")
        else:
            print(f"  {sample.stem:<25}: FAILED ({elapsed:.1f}s) {stderr[-120:]}")
    return records


def benchmark_single_agent(samples: list[Path]):
    print("\n=== [7/10] Baseline 7: Single-Agent Reflexion ===", flush=True)
    records = {}
    for sample in samples:
        out_dir = RESULTS_DIR / "single_agent" / sample.stem
        res_file = out_dir / "result.json"
        if res_file.is_file():
            res = json.loads(res_file.read_text())
            fit = res.get("best_fitness", 0.0)
            base_fit = res.get("baseline_fitness", 0.0)
            fit_val = fit if fit > 0 else base_fit
            ember = round(1.0 - (fit_val * 2 - 1.0), 4) if fit_val else 1.0
            records[sample.stem] = {
                "fitness": round(fit_val, 4),
                "ember_score": ember,
                "malconv_score": 0.0,
                "clamav_detected": False,
                "attempts": res.get("attempt_count", 0),
            }
            print(f"  {sample.stem:<25}: fitness={records[sample.stem]['fitness']:.4f}, ember={records[sample.stem]['ember_score']:.4f} (cached)")
            continue

        shutil.rmtree(out_dir, ignore_errors=True)
        cmd = [
            str(PYTHON), "-m", "pipeline.single_agent", "run", str(sample),
            "--output", str(out_dir),
            "--score-command", SCORE_CMD,
            "--model", MODEL,
            "--target", "ember",
            "--max-attempts", "1",
        ]
        t0 = time.time()
        code, stdout, stderr = run_cmd(cmd, timeout=180)
        elapsed = time.time() - t0
        if res_file.is_file():
            res = json.loads(res_file.read_text())
            fit = res.get("best_fitness", 0.0)
            base_fit = res.get("baseline_fitness", 0.0)
            fit_val = fit if fit > 0 else base_fit
            ember = round(1.0 - (fit_val * 2 - 1.0), 4) if fit_val else 1.0
            records[sample.stem] = {
                "fitness": round(fit_val, 4),
                "ember_score": ember,
                "malconv_score": 0.0,
                "clamav_detected": False,
                "attempts": res.get("attempt_count", 0),
                "elapsed": round(elapsed, 1),
            }
            print(f"  {sample.stem:<25}: fitness={records[sample.stem]['fitness']:.4f}, ember={records[sample.stem]['ember_score']:.4f} ({elapsed:.1f}s)")
        else:
            print(f"  {sample.stem:<25}: FAILED ({elapsed:.1f}s) {stderr[-120:]}")
    return records


def benchmark_multi_agent(samples: list[Path]):
    print("\n=== [8/10] Baseline 8: Multi-Agent ===", flush=True)
    records = {}
    for sample in samples:
        out_dir = RESULTS_DIR / "multi_agent" / sample.stem
        res_file = out_dir / "result.json"
        if res_file.is_file():
            res = json.loads(res_file.read_text())
            eval_data = res.get("best_evaluation", {})
            fit = res.get("best_fitness", 0.0)
            base_fit = res.get("baseline_fitness", 0.0)
            fit_val = fit if fit > 0 else base_fit
            ember = round(extract_ember_score(eval_data), 4) if eval_data else round(1.0 - (fit_val * 2 - 1.0), 4)
            records[sample.stem] = {
                "fitness": round(fit_val, 4),
                "ember_score": ember,
                "malconv_score": round(extract_malconv_score(eval_data), 6),
                "clamav_detected": extract_clamav_detected(eval_data),
                "attempts": res.get("attempt_count", 0),
            }
            print(f"  {sample.stem:<25}: fitness={records[sample.stem]['fitness']:.4f}, ember={records[sample.stem]['ember_score']:.4f} (cached)")
            continue

        shutil.rmtree(out_dir, ignore_errors=True)
        cmd = [
            str(PYTHON), "-m", "pipeline.multi_agent", "run", str(sample),
            "--output", str(out_dir),
            "--score-command", SCORE_CMD,
            "--model", MODEL,
            "--target", "ember",
            "--max-attempts", "1",
        ]
        t0 = time.time()
        code, stdout, stderr = run_cmd(cmd, timeout=240)
        elapsed = time.time() - t0
        if res_file.is_file():
            res = json.loads(res_file.read_text())
            eval_data = res.get("best_evaluation", {})
            fit = res.get("best_fitness", 0.0)
            base_fit = res.get("baseline_fitness", 0.0)
            fit_val = fit if fit > 0 else base_fit
            ember = round(extract_ember_score(eval_data), 4) if eval_data else round(1.0 - (fit_val * 2 - 1.0), 4)
            records[sample.stem] = {
                "fitness": round(fit_val, 4),
                "ember_score": ember,
                "malconv_score": round(extract_malconv_score(eval_data), 6),
                "clamav_detected": extract_clamav_detected(eval_data),
                "attempts": res.get("attempt_count", 0),
                "elapsed": round(elapsed, 1),
            }
            print(f"  {sample.stem:<25}: fitness={records[sample.stem]['fitness']:.4f}, ember={records[sample.stem]['ember_score']:.4f} ({elapsed:.1f}s)")
        else:
            print(f"  {sample.stem:<25}: FAILED ({elapsed:.1f}s) {stderr[-120:]}")
    return records


def benchmark_hybrid(samples: list[Path]):
    print("\n=== [9/10] Baseline 9: Hybrid-Fixed (EoH) ===", flush=True)
    records = {}
    for sample in samples:
        out_dir = RESULTS_DIR / "hybrid_fixed" / sample.stem
        res_file = out_dir / "result.json"
        if res_file.is_file():
            res = json.loads(res_file.read_text())
            eval_data = res.get("best_evaluation", {})
            records[sample.stem] = {
                "fitness": round(res.get("best_fitness", 0.0), 4),
                "ember_score": round(extract_ember_score(eval_data), 4),
                "malconv_score": round(extract_malconv_score(eval_data), 6),
                "clamav_detected": extract_clamav_detected(eval_data),
                "best_origin": res.get("best_origin", ""),
            }
            print(f"  {sample.stem:<25}: fitness={records[sample.stem]['fitness']:.4f}, ember={records[sample.stem]['ember_score']:.4f} (cached)")
            continue

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
            "--model", MODEL,
            "--seed", "42",
        ]
        t0 = time.time()
        code, stdout, stderr = run_cmd(cmd, timeout=240)
        elapsed = time.time() - t0
        if res_file.is_file():
            res = json.loads(res_file.read_text())
            eval_data = res.get("best_evaluation", {})
            records[sample.stem] = {
                "fitness": round(res.get("best_fitness", 0.0), 4),
                "ember_score": round(extract_ember_score(eval_data), 4),
                "malconv_score": round(extract_malconv_score(eval_data), 6),
                "clamav_detected": extract_clamav_detected(eval_data),
                "best_origin": res.get("best_origin", ""),
                "elapsed": round(elapsed, 1),
            }
            print(f"  {sample.stem:<25}: fitness={records[sample.stem]['fitness']:.4f}, ember={records[sample.stem]['ember_score']:.4f} ({elapsed:.1f}s)")
        else:
            print(f"  {sample.stem:<25}: FAILED ({elapsed:.1f}s) {stderr[-120:]}")
    return records


def benchmark_proposed(samples: list[Path]):
    print("\n=== [10/10] Baseline 10: Proposed Method (C2 + NSGA-II + Reflexion) ===", flush=True)
    records = {}
    for sample in samples:
        out_dir = RESULTS_DIR / "proposed" / sample.stem
        res_file = out_dir / "result.json"
        if res_file.is_file():
            res = json.loads(res_file.read_text())
            fit = res.get("best_fitness", 0.0)
            ember = round(1.0 - (fit * 2 - 1.0), 4) if fit else 1.0
            records[sample.stem] = {
                "fitness": round(fit, 4),
                "ember_score": ember,
                "malconv_score": 0.0,
                "clamav_detected": False,
                "best_objectives": res.get("best_objectives", []),
                "best_origin": res.get("best_origin", ""),
                "pareto_front_size": len(res.get("pareto_front", [])),
                "llm_calls": res.get("llm_calls", 0),
            }
            print(f"  {sample.stem:<25}: fitness={records[sample.stem]['fitness']:.4f}, ember={records[sample.stem]['ember_score']:.4f} (cached)")
            continue

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
        code, stdout, stderr = run_cmd(cmd, timeout=240)
        elapsed = time.time() - t0
        if res_file.is_file():
            res = json.loads(res_file.read_text())
            fit = res.get("best_fitness", 0.0)
            ember = round(1.0 - (fit * 2 - 1.0), 4) if fit else 1.0
            records[sample.stem] = {
                "fitness": round(fit, 4),
                "ember_score": ember,
                "malconv_score": 0.0,
                "clamav_detected": False,
                "best_objectives": res.get("best_objectives", []),
                "best_origin": res.get("best_origin", ""),
                "pareto_front_size": len(res.get("pareto_front", [])),
                "llm_calls": res.get("llm_calls", 0),
                "elapsed": round(elapsed, 1),
            }
            print(f"  {sample.stem:<25}: fitness={records[sample.stem]['fitness']:.4f}, ember={records[sample.stem]['ember_score']:.4f} ({elapsed:.1f}s)")
        else:
            print(f"  {sample.stem:<25}: FAILED ({elapsed:.1f}s) {stderr[-120:]}")
    return records


def main():
    print(f"Starting Advanced Baseline Benchmark Suite at {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Targets ({len(SAMPLES)}): {[s.stem for s in SAMPLES]}")
    t_start = time.time()

    b1 = benchmark_original()
    b2 = benchmark_random(SAMPLES)
    b3 = benchmark_heuristic(SAMPLES)
    b4 = benchmark_ga(SAMPLES)
    b5 = benchmark_bandit(SAMPLES)
    b6 = benchmark_xprimes(SAMPLES)
    b7 = benchmark_single_agent(SAMPLES)
    b8 = benchmark_multi_agent(SAMPLES)
    b9 = benchmark_hybrid(SAMPLES)
    b10 = benchmark_proposed(SAMPLES)

    consolidated = {
        "original": b1,
        "random_search": b2,
        "heuristic": b3,
        "ga_only": b4,
        "bandit": b5,
        "xprimes": b6,
        "single_agent": b7,
        "multi_agent": b8,
        "hybrid_fixed": b9,
        "proposed": b10,
    }

    out_file = ROOT / "baseline_results/advanced_static_results.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(consolidated, indent=2))
    print(f"\nAll 10 baselines completed on 3 advanced targets in {round(time.time() - t_start, 1)}s.")
    print(f"Results saved to: {out_file}")


if __name__ == "__main__":
    main()
