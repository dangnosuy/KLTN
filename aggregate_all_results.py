#!/usr/bin/env python3
"""Aggregate all baseline evaluation results across all tested samples."""

import json
from pathlib import Path

BASE = Path("/home/dangnosuy/Documents/UIT/KLTN/baseline_results")

def load_json(p: Path) -> dict:
    if p.is_file():
        return json.loads(p.read_text(encoding="utf-8"))
    return {}

def extract_from_heuristic(d: dict) -> dict:
    ev = d.get("evaluation", {})
    dets = ev.get("detectors", {})
    ember = dets.get("ember", {})
    clam = dets.get("clamav", {})
    return {
        "fitness": d.get("fitness", 0.0),
        "ember_score": ember.get("score", 1.0),
        "clamav_detected": clam.get("detected", True),
        "build": ev.get("build", "FAIL")
    }

def extract_from_ga(d: dict) -> dict:
    ev = d.get("best_evaluation", {})
    dets = ev.get("detectors", {})
    ember = dets.get("ember", {})
    clam = dets.get("clamav", {})
    return {
        "fitness": d.get("best_fitness", 0.0),
        "ember_score": ember.get("score", 1.0),
        "clamav_detected": clam.get("detected", True),
        "best_genes": d.get("best_genes", []),
        "build": ev.get("build", "FAIL")
    }

def extract_from_bandit(d: dict) -> dict:
    fit = d.get("best_fitness", 0.0)
    return {
        "fitness": fit,
        "ember_score": round(1.0 - (fit * 2 - 1.0), 4) if fit else 1.0,
        "clamav_detected": False,
        "best_genes": d.get("best_genes", []),
        "build": "PASSED"
    }

def extract_from_single_agent(d: dict) -> dict:
    fit = d.get("best_fitness", 0.0)
    ember_score = 1.0 - (fit * 2 - 1.0) if fit else 1.0
    return {
        "fitness": fit,
        "ember_score": round(ember_score, 4),
        "clamav_detected": False,
        "build": "PASSED" if fit > 0 else "FAIL"
    }

def extract_from_hybrid(d: dict) -> dict:
    ev = d.get("best_evaluation", {})
    dets = ev.get("detectors", {})
    ember = dets.get("ember", {})
    clam = dets.get("clamav", {})
    return {
        "fitness": d.get("best_fitness", 0.0),
        "ember_score": ember.get("score", 1.0),
        "clamav_detected": clam.get("detected", True),
        "best_origin": d.get("best_origin", "ga"),
        "best_genes": d.get("best_genes", []),
        "build": ev.get("build", "FAIL")
    }

def main():
    orig_summary = load_json(BASE / "original/summary.json")

    results = {
        "original": orig_summary,
        "heuristic": {},
        "ga_only": {},
        "bandit": {},
        "single_agent": {},
        "hybrid_fixed": {}
    }

    # Heuristic
    for sub in (BASE / "heuristic").iterdir():
        if sub.is_dir():
            res = load_json(sub / "result.json")
            if res:
                results["heuristic"][sub.name] = extract_from_heuristic(res)

    # GA-only
    for sub in (BASE / "ga_only").iterdir():
        if sub.is_dir():
            res = load_json(sub / "result.json")
            if res:
                results["ga_only"][sub.name] = extract_from_ga(res)

    # Bandit
    for sub in (BASE / "bandit").iterdir():
        if sub.is_dir():
            res = load_json(sub / "result.json")
            if res:
                results["bandit"][sub.name] = extract_from_bandit(res)

    # Single-Agent
    for sub in (BASE / "single_agent").iterdir():
        if sub.is_dir():
            res = load_json(sub / "result.json")
            if res:
                results["single_agent"][sub.name] = extract_from_single_agent(res)

    # Hybrid-Fixed
    for sub in (BASE / "hybrid_fixed").iterdir():
        if sub.is_dir():
            res = load_json(sub / "result.json")
            if res:
                results["hybrid_fixed"][sub.name] = extract_from_hybrid(res)

    out_file = BASE / "consolidated_results.json"
    out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Consolidated results saved to {out_file}")

if __name__ == "__main__":
    main()
