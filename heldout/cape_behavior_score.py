#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


STATIC_CATEGORIES = {"static", "packer", "obfuscation"}
STATIC_SIGNATURES = {"binary_yara", "procmem_yara"}
DYNAMIC_DATA_KEYS = {
    "command",
    "file",
    "process",
    "regkey",
    "suspicious_dll_load",
    "unbacked_library_loads",
    "unbacked_memory_threads",
    "unbacked_processes",
}
GROUPS = (
    ("memory_execution", {"allocation", "execution", "injection", "side loading"}, 5.0),
    ("command", {"command"}, 1.0),
    ("discovery", {"discovery", "location_discovery"}, 1.0),
    ("evasion", {"anti-av", "anti-debug", "anti-emulation", "anti-sandbox", "anti-vm", "evasion", "stealth"}, 1.0),
    ("persistence", {"persistence"}, 2.0),
    ("network", {"c2", "dns", "network"}, 2.0),
    ("credential_access", {"credential_access", "credential_dumping", "keylogger"}, 2.0),
    ("impact", {"encryption", "ransomware", "wiper"}, 2.0),
)
CHAIN_SIGNATURES = {
    "thread_unbacked_memory",
    "unbacked_library_load",
    "unbacked_process_creation",
}


def signature_points(signature):
    severity = signature.get("severity", 1)
    base = 0.5 if severity == 1 else severity - 1
    return base * signature.get("weight", 1) * signature.get("confidence", 100) / 100


def has_dynamic_evidence(signature):
    if signature.get("name") in STATIC_SIGNATURES:
        return False
    categories = set(signature.get("categories", []))
    if categories and categories <= STATIC_CATEGORIES:
        return False
    for item in signature.get("data", []):
        if not isinstance(item, dict):
            continue
        if {"cid", "pid"} <= item.keys() or DYNAMIC_DATA_KEYS & item.keys():
            return True
    return False


def signature_group(signature):
    categories = set(signature.get("categories", []))
    for name, group_categories, _ in GROUPS:
        if categories & group_categories:
            return name
    return "other"


def process_metrics(report):
    processes = report.get("behavior", {}).get("processes", [])
    return len(processes), sum(len(process.get("calls", [])) for process in processes)


def score_report(report):
    process_count, api_call_count = process_metrics(report)
    if not report.get("behavior", {}).get("processtree"):
        return {
            "status": "NO_TELEMETRY",
            "verdict": "INFRA_FAILURE",
            "score": None,
            "process_count": process_count,
            "api_call_count": api_call_count,
            "evidence": [],
            "excluded_signatures": [sig.get("name") for sig in report.get("signatures", [])],
        }

    dynamic = [sig for sig in report.get("signatures", []) if has_dynamic_evidence(sig)]
    grouped = {}
    for signature in dynamic:
        group = signature_group(signature)
        grouped.setdefault(group, []).append(signature)

    dimensions = []
    total = 0.0
    caps = {name: cap for name, _, cap in GROUPS} | {"other": 1.0}
    for group, signatures in grouped.items():
        points = min(sum(signature_points(sig) for sig in signatures), caps[group])
        total += points
        dimensions.append({
            "name": group,
            "score": round(points, 2),
            "cap": caps[group],
            "signatures": [sig["name"] for sig in signatures],
        })

    names = {signature["name"] for signature in dynamic}
    chain_bonus = 1.0 if CHAIN_SIGNATURES <= names else 0.0
    score = round(min(total + chain_bonus, 10.0), 2)
    verdict = "HIGH_RISK" if score >= 7 else "SUSPICIOUS" if score >= 4 else "OBSERVED"
    return {
        "status": "COMPLETED",
        "verdict": verdict,
        "score": score,
        "process_count": process_count,
        "api_call_count": api_call_count,
        "chain_bonus": chain_bonus,
        "dimensions": sorted(dimensions, key=lambda item: item["name"]),
        "evidence": [signature["name"] for signature in dynamic],
        "excluded_signatures": [
            signature.get("name")
            for signature in report.get("signatures", [])
            if signature not in dynamic
        ],
    }


def summarize(report):
    target = report.get("target", {}).get("file", {})
    return {
        "task_id": report.get("info", {}).get("id"),
        "sample": target.get("name"),
        "sha256": target.get("sha256"),
        "cape_malscore": report.get("malscore"),
        "behavior": score_report(report),
    }


def main():
    parser = argparse.ArgumentParser(description="Score a CAPE report using dynamic behavior only")
    parser.add_argument("report", type=Path, help="Path to CAPE report.json")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    result = summarize(json.loads(args.report.read_text(encoding="utf-8")))
    rendered = json.dumps(result, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if result["behavior"]["status"] == "COMPLETED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
