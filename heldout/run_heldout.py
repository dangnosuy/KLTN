#!/usr/bin/env python3
import argparse
import hashlib
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
TOOLS = ROOT / ".tools"
CAPA_BIN = TOOLS / "capa" / "capa"
QV_DIR = TOOLS / "quo-vadis"
QV_PYTHON = QV_DIR / "venv" / "bin" / "python"
QV_RUNNER = ROOT / "quo_vadis_runner.py"
POLICY_PATH = ROOT / "policy.json"
SUPPORTED_SUFFIXES = {".exe", ".dll"}


def load_policy():
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def collect_samples(target):
    if target.is_file():
        return [target.resolve()]
    if target.is_dir():
        return sorted(
            path.resolve()
            for path in target.rglob("*")
            if path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES
        )
    raise FileNotFoundError(f"Target not found: {target}")


def file_metadata(path):
    content = path.read_bytes()
    return {
        "filename": path.name,
        "path": str(path),
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def run_json(command, timeout):
    completed = subprocess.run(
        [str(part) for part in command],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(detail[-1000:] or f"process exited {completed.returncode}")
    return json.loads(completed.stdout)


def scan_capa(sample, policy, timeout):
    started = time.monotonic()
    document = run_json([CAPA_BIN, "-j", sample], timeout)
    result = classify_capa(document, policy)
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return result


def classify_capa(document, policy):
    matched_rules = []
    matched_attack_ids = set()
    for name, rule in document.get("rules", {}).items():
        metadata = rule.get("meta", {})
        attack_ids = sorted(
            item.get("id") for item in metadata.get("attack", []) if item.get("id")
        )
        matched_attack_ids.update(attack_ids)
        if not metadata.get("lib", False):
            matched_rules.append({
                "name": name,
                "namespace": metadata.get("namespace", ""),
                "attack_ids": attack_ids,
            })

    high_risk = set(policy["capa_high_risk_attack_ids"])
    triggered_attack_ids = sorted(matched_attack_ids & high_risk)
    namespace_prefixes = tuple(policy["capa_high_risk_namespace_prefixes"])
    triggered_rules = sorted(
        rule["name"] for rule in matched_rules if rule["namespace"].startswith(namespace_prefixes)
    )
    return {
        "status": "COMPLETED",
        "detected": bool(triggered_attack_ids or triggered_rules),
        "verdict": "DETECTED" if triggered_attack_ids or triggered_rules else "NOT_DETECTED",
        "policy": "high-risk ATT&CK ID or capability namespace match",
        "triggered_attack_ids": triggered_attack_ids,
        "triggered_rules": triggered_rules,
        "matched_attack_ids": sorted(matched_attack_ids),
        "matched_rule_count": len(matched_rules),
        "matched_rules": matched_rules,
        "capa_version": document.get("meta", {}).get("version"),
    }


def scan_quo_vadis(sample, policy, timeout):
    return run_json([
        QV_PYTHON,
        QV_RUNNER,
        sample,
        "--assets",
        QV_DIR,
        "--threshold",
        str(policy["quo_vadis_threshold"]),
    ], timeout)


def doctor(engines):
    checks = {}
    if "capa" in engines:
        if not CAPA_BIN.is_file():
            checks["capa"] = {"status": "ERROR", "error": f"Missing {CAPA_BIN}"}
        else:
            completed = subprocess.run([CAPA_BIN, "--version"], capture_output=True, text=True)
            checks["capa"] = {
                "status": "READY" if completed.returncode == 0 else "ERROR",
                "version": completed.stdout.strip(),
            }
    if "quo-vadis" in engines:
        if not QV_PYTHON.is_file():
            checks["quo-vadis"] = {"status": "ERROR", "error": f"Missing {QV_PYTHON}"}
        else:
            try:
                checks["quo-vadis"] = run_json(
                    [QV_PYTHON, QV_RUNNER, "--assets", QV_DIR, "--doctor"], 30
                )
            except Exception as exc:
                checks["quo-vadis"] = {"status": "ERROR", "error": str(exc)}
    print(json.dumps(checks, indent=2))
    return 0 if all(item["status"] == "READY" for item in checks.values()) else 2


def parse_engines(value):
    engines = [item.strip().lower() for item in value.split(",") if item.strip()]
    if not engines:
        raise argparse.ArgumentTypeError("At least one engine is required")
    unknown = set(engines) - {"capa", "quo-vadis"}
    if unknown:
        raise argparse.ArgumentTypeError(f"Unknown engines: {', '.join(sorted(unknown))}")
    return engines


def print_result(index, total, sample, engine, result):
    status = result.get("status", "ERROR")
    verdict = result.get("verdict", "N/A")
    detail = ""
    if engine == "capa" and status == "COMPLETED":
        detail = (
            f"ATT&CK={','.join(result['triggered_attack_ids']) or '-'} "
            f"high-risk={len(result['triggered_rules'])} rules={result['matched_rule_count']}"
        )
    elif engine == "quo-vadis" and status == "COMPLETED":
        detail = f"score={result['score']:.4f} APIs={result['api_call_count']}"
    else:
        detail = result.get("error", "")
    print(f"[{index:02d}/{total}] {engine:<11} {verdict:<12} {sample.name}  {detail}")


def run_campaign(target, engines, output, timeout):
    samples = collect_samples(target)
    if not samples:
        raise RuntimeError("No .exe or .dll samples found")
    policy = load_policy()
    jobs = [(sample, engine) for sample in samples for engine in engines]
    report = {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "purpose": "held-out evaluation only; never use as optimization feedback",
        "policy": policy,
        "results": [],
    }

    for index, (sample, engine) in enumerate(jobs, 1):
        try:
            result = (
                scan_capa(sample, policy, timeout)
                if engine == "capa"
                else scan_quo_vadis(sample, policy, timeout)
            )
        except Exception as exc:
            result = {"status": "ERROR", "error": f"{type(exc).__name__}: {exc}"}
        row = {"sample": file_metadata(sample), "engine": engine, "result": result}
        report["results"].append(row)
        print_result(index, len(jobs), sample, engine, result)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    errors = sum(row["result"].get("status") != "COMPLETED" for row in report["results"])
    print(f"Report: {output} ({len(jobs) - errors}/{len(jobs)} completed)")
    return 0 if errors == 0 else 2


def main():
    parser = argparse.ArgumentParser(description="Independent held-out detector cluster")
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor_parser = subparsers.add_parser("doctor")
    doctor_parser.add_argument("--engines", type=parse_engines, default=["capa", "quo-vadis"])

    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("target", type=Path)
    run_parser.add_argument("--engines", type=parse_engines, default=["capa", "quo-vadis"])
    run_parser.add_argument("--output", type=Path, default=ROOT / "reports" / "heldout.json")
    run_parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()

    if args.command == "doctor":
        return doctor(args.engines)
    return run_campaign(args.target, args.engines, args.output, args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())

