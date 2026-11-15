from __future__ import annotations

import io
import json
import os
import time
import zipfile
from pathlib import Path, PureWindowsPath

import requests

from heldout.cape_behavior_score import has_dynamic_evidence, score_report
from .core import digest, failed, log, result, unchanged, write_json


def bundle(sample):
    unchanged(sample)
    if len(sample["artifacts"]) == 1:
        item = sample["artifacts"][0]
        return item["name"], Path(item["path"]).read_bytes(), "exe", ""
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for artifact in sample["artifacts"]:
            info = zipfile.ZipInfo(artifact["name"], date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            with open(artifact["path"], "rb") as handle:
                archive.writestr(info, handle.read())
    return "sample.zip", stream.getvalue(), "zip", f"file={sample['name']}"


def score_task(report, sample, task_id, submission_sha256, threshold):
    if report.get("info", {}).get("id") != task_id:
        raise ValueError("CAPE report task ID mismatch")
    target_hash = report.get("target", {}).get("file", {}).get("sha256", "").lower()
    if target_hash != submission_sha256:
        raise ValueError("CAPE report input hash mismatch")
    if len(sample["artifacts"]) > 1:
        options = report.get("info", {}).get("options", {})
        if isinstance(options, str):
            options = dict(part.split("=", 1) for part in options.split(",") if "=" in part)
        if options.get("file") != sample["name"]:
            raise ValueError("CAPE ZIP entrypoint mismatch")
    behavior = report.get("behavior") or {}
    trees = behavior.get("processtree") or []
    matches = []

    def visit(nodes):
        for node in nodes:
            name = node.get("name") or node.get("process_name") or node.get("module_path") or ""
            if PureWindowsPath(name).name.casefold() == sample["name"].casefold():
                matches.append(node)
            visit(node.get("children") or [])

    visit(trees)
    pids = set()

    def lineage(nodes):
        for node in nodes:
            pid = node.get("pid", node.get("process_id"))
            if pid is not None:
                pids.add(str(pid))
            lineage(node.get("children") or [])

    lineage(matches)
    processes = [process for process in behavior.get("processes", []) if str(process.get("process_id")) in pids]
    if not matches or not any(process.get("calls") for process in processes):
        return failed("CAPE has no API telemetry attributable to the sample/process lineage", "INFRA_FAILURE")
    dynamic = []
    for signature in report.get("signatures", []):
        if not has_dynamic_evidence(signature):
            continue
        data = signature.get("data", [])
        evidence_pids = {str(item["pid"]) for item in data if isinstance(item, dict) and "pid" in item}
        if evidence_pids and not evidence_pids & pids:
            continue
        dynamic.append(signature)
    scoped = {**report, "behavior": {**behavior, "processtree": matches, "processes": processes}, "signatures": dynamic}
    scored = score_report(scoped)
    score = scored["score"]
    if scored["status"] != "COMPLETED" or score is None:
        return failed("CAPE behavior scorer could not evaluate runtime evidence", "INFRA_FAILURE")
    return result(
        score >= threshold,
        score=score,
        threshold=threshold,
        behavior_verdict=scored["verdict"],
        behavior=scored,
        telemetry="OBSERVED",
        cape_malscore=report.get("malscore"),
        version={"cape": report.get("info", {}).get("version"), "scorer_sha256": digest(Path(__file__).resolve().parents[2] / "heldout/cape_behavior_score.py")},
        excluded_signatures=[item.get("name") for item in report.get("signatures", []) if item not in dynamic],
    )


class CapeScanner:
    def __init__(self, config):
        self.config = config["cape"]
        self.url = self.config["url"].rstrip("/")
        self.session = requests.Session()
        self.session.trust_env = False
        token = os.getenv("CAPE_API_TOKEN")
        if token:
            self.session.headers["Authorization"] = f"Token {token}"

    def request(self, method, endpoint, **kwargs):
        response = self.session.request(method, self.url + "/apiv2/" + endpoint, timeout=self.config["request_timeout"], verify=self.config["verify_tls"], allow_redirects=False, **kwargs)
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict) or payload.get("error"):
            raise RuntimeError("CAPE API rejected request; check API access/configuration")
        return payload

    def doctor(self):
        status = self.request("GET", "cuckoo/status/")
        machines = self.request("GET", "machines/list/")
        rows = machines.get("data", [])
        if isinstance(rows, dict):
            rows = rows.get("machines", [])
        windows = [row for row in rows if row.get("platform") == "windows"]
        selected = self.config["machine"]
        if not windows or (selected and not any(selected in (row.get("name"), row.get("label")) for row in windows)):
            raise RuntimeError("No matching Windows machine is registered in CAPE")
        return {"api": "reachable", "machine": selected or "CAPE scheduler default", "windows_machine_count": len(windows), "status": status.get("data", {})}

    def scan(self, sample, directory):
        import hashlib
        directory.mkdir(parents=True, exist_ok=True)
        state_path = directory / "cape-task.json"
        name, content, package, options = bundle(sample)
        submission_sha256 = hashlib.sha256(content).hexdigest()
        state = json.loads(state_path.read_text()) if state_path.exists() else {}
        if state and (state.get("submission_sha256") != submission_sha256 or state.get("package_sha256") != sample["package_sha256"]):
            raise ValueError("CAPE resume input/package mismatch")
        if not state:
            state = {"package_sha256": sample["package_sha256"], "submission_sha256": submission_sha256, "state": "SUBMITTING"}
            write_json(state_path, state)
            # Never retry an ambiguous POST automatically: the server may have accepted it.
            submitted = self.request("POST", "tasks/create/file/", files={"file": (name, content)}, data={"package": package, "options": options, "timeout": self.config["analysis_timeout"], "machine": self.config["machine"], "platform": "windows", "unique": "0", "custom": f"detectors-{sample['package_sha256']}"})
            task_ids = submitted.get("data", {}).get("task_ids", [])
            if len(task_ids) != 1 or isinstance(task_ids[0], bool) or not isinstance(task_ids[0], int) or task_ids[0] <= 0:
                raise RuntimeError("CAPE did not return exactly one task ID; submission state retained for inspection")
            state.update(task_id=task_ids[0], state="SUBMITTED")
            write_json(state_path, state)
        task_id = state.get("task_id")
        if not isinstance(task_id, int) or isinstance(task_id, bool) or task_id <= 0:
            raise RuntimeError("CAPE submission outcome is uncertain; inspect the task list and resolve cape-task.json before retrying (no duplicate POST sent)")
        log(f"CAPE task={task_id} {self.url}/analysis/{task_id}/")
        deadline = time.monotonic() + self.config["timeout"]
        report_path = directory / "cape-report.json"
        while time.monotonic() < deadline:
            status = self.request("GET", f"tasks/status/{task_id}/").get("data")
            log(f"CAPE task={task_id} status={status}; elapsed budget remaining={max(0, int(deadline-time.monotonic()))}s")
            if str(status).startswith("failed") or status in ("banned", "distributed", "recovered"):
                return failed(f"CAPE task {task_id}: {status}", "INFRA_FAILURE")
            if status == "reported":
                report = self.request("GET", f"tasks/get/report/{task_id}/json/")
                write_json(report_path, report)
                response = score_task(report, sample, task_id, submission_sha256, self.config["threshold"])
                response.update(task_id=task_id, task_url=f"{self.url}/analysis/{task_id}/", raw_report=str(report_path))
                return response
            time.sleep(min(self.config["poll_interval"], max(0, deadline-time.monotonic())))
        return failed(f"CAPE task {task_id} not reported within {self.config['timeout']}s; task retained for resume", "INFRA_FAILURE")

    def close(self):
        self.session.close()
