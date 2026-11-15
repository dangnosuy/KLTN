from __future__ import annotations

import csv
import fcntl
import json
import os
import re
import shutil
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path

from .cape import CapeScanner
from .core import ENGINES, ROOT, digest, failed, json_hash, local_path, log, now, package, result, unchanged, write_json
from .defender import DefenderScanner
from .static import StaticScanner


@contextmanager
def lock(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        os.chmod(path, 0o600)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError(f"Resource is already in use: {path.name}") from error
        yield


def fingerprint(config):
    assets = {}
    for key in ("ember_model", "malconv_model"):
        path = local_path(config["static"][key])
        assets[key] = digest(path) if path.is_file() else "MISSING"
    for path in (
        ROOT / "Signature-base/ML-based/EMBER2024/src/thrember/features.py",
        ROOT / "Signature-base/malconv_official.py",
        ROOT / "heldout/cape_behavior_score.py",
        *sorted(Path(__file__).parent.glob("*.py")),
    ):
        assets[str(path.relative_to(ROOT))] = digest(path)
    return json_hash({"config": config, "assets": assets}), assets


def safe_error(error):
    message = str(error)
    for name in ("VM_GUEST_PASSWORD", "VMRUN_VM_PASSWORD", "CAPE_API_TOKEN"):
        secret = os.getenv(name)
        if secret:
            message = message.replace(secret, "<redacted>")
    return message[:2000]


def directory_inputs(target):
    paths = []
    for path in sorted(target.rglob("*")):
        if not path.is_file() or path.suffix.lower() != ".exe":
            continue
        manifest = path.parent / "manifest.json"
        if manifest.exists():
            document = json.loads(manifest.read_text(encoding="utf-8"))
            if not isinstance(document, dict) or not isinstance(document.get("samples"), dict):
                raise ValueError("manifest.json must contain a samples object")
            entry = document["samples"].get(path.name, {})
            if not isinstance(entry, dict):
                raise ValueError("Invalid sample manifest entry")
            ready = entry.get("benchmark_ready", True)
            if not isinstance(ready, bool):
                raise ValueError("benchmark_ready must be a boolean")
            if not ready:
                log(f"EXCLUDED {path.name}: benchmark_ready=false")
                continue
        paths.append(path)
    return paths


def aggregate(artifacts):
    failures = [item for item in artifacts if item["status"] != "COMPLETED"]
    if failures:
        detail = "; ".join(f"{item.get('name', 'artifact')}: {item.get('error', item['status'])}" for item in failures)
        combined = failed(detail[:2000], "INFRA_FAILURE" if any(item["status"] == "INFRA_FAILURE" for item in failures) else "ERROR")
    else:
        combined = result(any(item["detected"] for item in artifacts))
        scores = [item["score"] for item in artifacts if "score" in item]
        if scores:
            combined.update(score=max(scores), threshold=artifacts[0]["threshold"], score_aggregation="max_over_artifacts")
        combined["version"] = artifacts[0].get("version", {})
    combined["artifacts"] = artifacts
    return combined


class DetectorRunner:
    def __init__(self, config):
        self.config = config
        self.static = StaticScanner(config)
        self.defender = DefenderScanner(config)
        self.cape = CapeScanner(config)

    def close(self):
        self.defender.close()
        self.cape.close()

    def doctor(self, engines):
        checks = {}
        for engine in engines:
            log(f"DOCTOR {engine.upper()}")
            started = time.monotonic()
            try:
                details = self.static.doctor(engine) if engine in ENGINES[:3] else getattr(self, engine).doctor()
                checks[engine] = {"ready": True, **details}
            except Exception as error:
                checks[engine] = {"ready": False, "error": safe_error(error)}
            checks[engine]["duration_seconds"] = round(time.monotonic() - started, 3)
            log(f"{engine.upper()} {'READY' if checks[engine]['ready'] else 'NOT READY'} {checks[engine].get('error', '')}")
        return {"checked_at": now(), "engines": checks, "ready": all(item["ready"] for item in checks.values())}

    def scan_engine(self, engine, sample, directory, manifest, manifest_path):
        unchanged(sample)
        if engine == "cape":
            response = self.cape.scan(sample, directory)
        else:
            items = []
            for index, artifact in enumerate(sample["artifacts"]):
                log(f"{engine.upper()} artifact={artifact['name']} role={artifact['role']}")
                unchanged(sample)
                try:
                    response = self.defender.scan(artifact) if engine == "defender" else self.static.scan(engine, artifact)
                except Exception as error:
                    response = failed(safe_error(error), "INFRA_FAILURE" if engine == "defender" else "ERROR")
                response.update(name=artifact["name"], role=artifact["role"], sha256=artifact["sha256"])
                evidence = directory / f"{engine}-{index}.json"
                write_json(evidence, response)
                if response["status"] == "COMPLETED":
                    self.pin_version(engine, response, manifest, manifest_path)
                response = {key: value for key, value in response.items() if key not in ("stdout", "stderr")}
                response["raw_evidence"] = str(evidence)
                items.append(response)
            response = aggregate(items)
        if response["status"] == "COMPLETED":
            self.pin_version(engine, response, manifest, manifest_path)
        unchanged(sample)
        return response

    @staticmethod
    def pin_version(engine, response, manifest, manifest_path):
        version = response.get("version", {})
        previous = manifest["versions"].get(engine)
        if previous is not None and previous != version:
            raise RuntimeError(f"{engine} version/database changed within campaign; use a new campaign")
        if previous is None:
            manifest["versions"][engine] = version
            write_json(manifest_path, manifest)

    def run(self, target, campaign, engines, c1_path=None):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}", campaign):
            raise ValueError("campaign must be a simple identifier, not a path")
        paths = [target] if target.is_file() else directory_inputs(target)
        if not paths:
            raise ValueError("No EXE inputs found")
        samples = list({item["package_sha256"]: item for item in (package(path) for path in paths)}.values())
        c1 = None
        if c1_path:
            if len(samples) != 1:
                raise ValueError("--c1 accepts one sample at a time")
            c1 = json.loads(c1_path.read_text(encoding="utf-8"))
            if not isinstance(c1, dict) or not isinstance(c1.get("sha256"), str) or c1["sha256"].lower() != samples[0]["sha256"] or c1.get("status") not in ("PASS", "BUILD_FAIL", "UNDETERMINED"):
                raise ValueError("C1 requires matching sha256 and status PASS/BUILD_FAIL/UNDETERMINED")
        campaign_dir = local_path(self.config["output_dir"]) / campaign
        with ExitStack() as stack:
            stack.enter_context(lock(campaign_dir / ".lock"))
            if "defender" in engines:
                vmx = str(Path(os.getenv("VMRUN_VMX", "missing-vmx")).expanduser().resolve())
                vm_key = json_hash(vmx)
                stack.enter_context(lock(Path("/tmp") / f"thesis-defender-{vm_key}.lock"))
            signature, assets = fingerprint(self.config)
            manifest_path = campaign_dir / "manifest.json"
            manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {"campaign": campaign, "created_at": now(), "config_fingerprint": signature, "config": self.config, "assets": assets, "versions": {}, "samples": []}
            if manifest["config_fingerprint"] != signature:
                raise ValueError("Campaign configuration/model/code changed; use a new --campaign")
            write_json(manifest_path, manifest)
            log(f"CAMPAIGN {campaign} samples={len(samples)} engines={','.join(engines)}")
            started = time.monotonic()
            registered = []
            for number, sample in enumerate(samples, 1):
                key = sample["package_sha256"]
                directory = campaign_dir / "evidence" / key
                report_path = campaign_dir / "samples" / f"{key}.json"
                report = json.loads(report_path.read_text()) if report_path.exists() else {"sample": sample, "created_at": now(), "engines": {engine: result(status="SKIPPED") for engine in ENGINES}}
                if c1 is not None:
                    report["c1"] = c1
                log(f"SAMPLE [{number}/{len(samples)}] {sample['name']} sha256={sample['sha256'][:16]}")
                # Immutable campaign copies keep the Defender/CAPE input identical to local scans.
                for artifact in sample["artifacts"]:
                    source = Path(artifact["path"])
                    destination = campaign_dir / "inputs" / key / artifact["name"]
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    if not destination.exists():
                        shutil.copyfile(source, destination)
                    if digest(destination) != artifact["sha256"]:
                        raise ValueError("Campaign input copy hash mismatch")
                    artifact["original_path"] = artifact["path"]
                    artifact["path"] = str(destination)
                report["sample"] = sample
                if key not in manifest["samples"]:
                    manifest["samples"].append(key)
                    write_json(manifest_path, manifest)
                write_json(report_path, report)
                registered.append((sample, directory, report_path, report))
            for engine in engines:
                for number, (sample, directory, report_path, report) in enumerate(registered, 1):
                    log(f"JOB {engine.upper()} [{number}/{len(registered)}] {sample['name']}")
                    if report["engines"][engine]["status"] == "COMPLETED":
                        log(f"{engine.upper()} RESUMED {report['engines'][engine]['verdict']}")
                        continue
                    tick = time.monotonic()
                    log(f"{engine.upper()} START")
                    try:
                        response = self.scan_engine(engine, sample, directory, manifest, manifest_path)
                    except Exception as error:
                        response = failed(safe_error(error), "INFRA_FAILURE" if engine in ("defender", "cape") else "ERROR")
                    response["duration_seconds"] = round(time.monotonic() - tick, 3)
                    response["completed_at"] = now()
                    report["engines"][engine] = response
                    write_json(report_path, report)
                    label = response["verdict"] if response["status"] == "COMPLETED" else response["status"]
                    score = f" score={response['score']} threshold={response.get('threshold')}" if "score" in response else ""
                    log(f"{engine.upper()} {label} elapsed={response['duration_seconds']:.1f}s{score} {response.get('error', '')}")
                    self.summarize(campaign_dir, manifest)
                if engine == "defender":
                    self.defender.close()
            summary = self.summarize(campaign_dir, manifest)
            log(f"CAMPAIGN FINISHED elapsed={time.monotonic()-started:.1f}s detected={summary['counts']['detected']} no_alert={summary['counts']['no_alert']} errors={summary['counts']['errors']} skipped={summary['counts']['skipped']}")
            self.print_table(summary["rows"])
            log(f"REPORT {campaign_dir / 'summary.json'}")
            return summary

    @staticmethod
    def summarize(directory, manifest):
        rows = []
        counts = {"detected": 0, "no_alert": 0, "errors": 0, "skipped": 0}
        for key in manifest["samples"]:
            path = directory / "samples" / f"{key}.json"
            if not path.exists():
                continue
            report = json.loads(path.read_text())
            for engine in ENGINES:
                item = report["engines"][engine]
                rows.append({"sample": report["sample"]["name"], "sha256": report["sample"]["sha256"], "package_sha256": key, "engine": engine, "status": item["status"], "verdict": item["verdict"], "detected": item["detected"], "score": item.get("score"), "threshold": item.get("threshold"), "duration_seconds": item.get("duration_seconds"), "task_id": item.get("task_id"), "error": item.get("error")})
                field = "skipped" if item["status"] == "SKIPPED" else "errors" if item["status"] != "COMPLETED" else "detected" if item["detected"] else "no_alert"
                counts[field] += 1
        summary = {"campaign": manifest["campaign"], "updated_at": now(), "status": "PARTIAL" if counts["errors"] or counts["skipped"] else "COMPLETED", "counts": counts, "rows": rows}
        write_json(directory / "summary.json", summary)
        temporary = directory / "summary.csv.tmp"
        with temporary.open("w", encoding="utf-8", newline="") as handle:
            if rows:
                writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
                writer.writeheader()
                # Filenames and scanner messages are untrusted spreadsheet cells.
                writer.writerows({key: "'" + value if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")) else value for key, value in row.items()} for row in rows)
        temporary.replace(directory / "summary.csv")
        return summary

    @staticmethod
    def print_table(rows):
        print(f"{'SAMPLE':32} {'ENGINE':10} {'RESULT':15} {'SCORE':9} {'SECONDS':>8}", flush=True)
        for row in rows:
            state = row["verdict"] if row["status"] == "COMPLETED" else row["status"]
            score = "-" if row["score"] is None else f"{row['score']:.4g}"
            seconds = "-" if row["duration_seconds"] is None else f"{row['duration_seconds']:.1f}"
            print(f"{row['sample'][:32]:32} {row['engine']:10} {state:15} {score:9} {seconds:>8}", flush=True)
