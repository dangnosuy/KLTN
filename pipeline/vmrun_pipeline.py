#!/usr/bin/env python3
"""VMware Tools based dynamic benchmark runner.

This runner is intentionally separate from the SMB watcher pipeline. It owns a
single VM and runs one sample at a time, reverting to a clean snapshot first.
"""
from __future__ import annotations

import argparse
import base64
import csv
import fcntl
import hashlib
import json
import os
import random
import re
import subprocess
import sys
import time
import warnings
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def suppress_warnings() -> None:
    warnings.simplefilter("ignore")


suppress_warnings()

import requests


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = BASE_DIR / "pipeline" / "vmrun_reports"
SNAPSHOTS = {
    "defender": os.getenv("VMRUN_SNAPSHOT_DEFENDER", "normal_real"),
    "elastic": os.getenv("VMRUN_SNAPSHOT_ELASTIC", "elastic"),
    "wazuh": os.getenv("VMRUN_SNAPSHOT_WAZUH", "wazuh"),
}
SERVICE_UNITS = {
    "elastic": ("elasticsearch", "kibana", "elastic-agent"),
    "wazuh": ("wazuh-indexer", "wazuh-manager", "wazuh-dashboard"),
}
SAMPLE_MANIFEST = "manifest.json"


class PipelineError(RuntimeError):
    pass


class ExecutionFailure(PipelineError):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utcnow().isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def atomic_json_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")
    temporary.replace(path)


def sample_metadata(sample: Path) -> dict[str, Any]:
    manifest_path = sample.parent / SAMPLE_MANIFEST
    if not manifest_path.is_file():
        return {}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PipelineError(f"Invalid sample manifest {manifest_path}: {error}") from error
    samples = manifest.get("samples")
    if not isinstance(samples, dict):
        raise PipelineError(f"Sample manifest must contain an object named 'samples': {manifest_path}")
    metadata = samples.get(sample.name, {})
    if not isinstance(metadata, dict):
        raise PipelineError(f"Manifest entry for {sample.name} must be an object")
    return metadata


def sample_companions(sample: Path) -> list[Path]:
    companions = sample_metadata(sample).get("companions", [])
    if not isinstance(companions, list) or not all(isinstance(item, str) for item in companions):
        raise PipelineError(f"Manifest companions for {sample.name} must be a list of filenames")
    paths = []
    seen = {sample.name.casefold()}
    for name in companions:
        if (not name or Path(name).name != name or "/" in name or "\\" in name or
                any(char in name for char in '<>:"|?*')):
            raise PipelineError(f"Companion must be a filename in the sample directory: {name}")
        normalized = name.casefold()
        if normalized in seen:
            raise PipelineError(f"Duplicate artifact filename for {sample.name}: {name}")
        seen.add(normalized)
        path = sample.parent / name
        if not path.is_file():
            raise PipelineError(f"Missing companion for {sample.name}: {path}")
        paths.append(path)
    return paths


def sample_artifacts(sample: Path, sample_digest: str | None = None) -> list[dict[str, Any]]:
    return [
        {"role": "primary", "name": sample.name, "path": sample, "sha256": sample_digest or sha256_file(sample)},
        *[
            {"role": "companion", "name": path.name, "path": path, "sha256": sha256_file(path)}
            for path in sample_companions(sample)
        ],
    ]


def sample_package_sha256(sample: Path, sample_digest: str | None = None) -> str:
    artifacts = sample_artifacts(sample, sample_digest)
    if len(artifacts) == 1:
        return artifacts[0]["sha256"]
    identity = [{"name": item["name"], "role": item["role"], "sha256": item["sha256"]}
                for item in sorted(artifacts, key=lambda value: value["name"].casefold())]
    return hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def tls_verify() -> bool | str:
    ca_file = os.getenv("EDR_CA_CERT")
    if ca_file:
        return ca_file
    return os.getenv("EDR_INSECURE_TLS") != "1"


def basic_auth(prefix: str) -> tuple[str, str] | None:
    user = os.getenv(f"{prefix}_USER")
    password = os.getenv(f"{prefix}_PASS")
    if bool(user) != bool(password):
        raise PipelineError(f"Set both {prefix}_USER and {prefix}_PASS, or neither.")
    return (user, password) if user else None


@dataclass(frozen=True)
class Settings:
    vmx: Path
    guest_user: str
    guest_password: str
    vm_password: str | None
    output_dir: Path
    static_wait: int
    detonation_wait: int
    poll_wait: int
    poll_attempts: int
    tools_timeout: int
    clock_skew_max: int
    elastic_ready_timeout: int = 420
    elastic_canary_timeout: int = 360
    elastic_poll_attempts: int = 24
    elastic_agent_max_checkin_age: int = 45
    guest_health_timeout: int = 60
    execution_proof_timeout: int = 30

    @classmethod
    def from_env(cls, output_dir: Path | None = None) -> "Settings":
        required = ("VMRUN_VMX", "VM_GUEST_USER", "VM_GUEST_PASSWORD")
        absent = [name for name in required if not os.getenv(name)]
        if absent:
            raise PipelineError("Missing required environment variables: " + ", ".join(absent))
        vmx = Path(os.environ["VMRUN_VMX"]).expanduser()
        if not vmx.is_file():
            raise PipelineError(f"VMX does not exist: {vmx}")
        return cls(
            vmx=vmx,
            guest_user=os.environ["VM_GUEST_USER"],
            guest_password=os.environ["VM_GUEST_PASSWORD"],
            vm_password=os.getenv("VMRUN_VM_PASSWORD"),
            output_dir=output_dir or Path(os.getenv("VMRUN_OUTPUT_DIR", DEFAULT_OUTPUT)),
            static_wait=int(os.getenv("VMRUN_STATIC_WAIT_SECONDS", "10")),
            detonation_wait=int(os.getenv("VMRUN_DETONATION_SECONDS", "20")),
            poll_wait=int(os.getenv("VMRUN_POLL_SECONDS", "5")),
            poll_attempts=int(os.getenv("VMRUN_POLL_ATTEMPTS", "6")),
            tools_timeout=int(os.getenv("VMRUN_TOOLS_TIMEOUT_SECONDS", "120")),
            clock_skew_max=int(os.getenv("VMRUN_CLOCK_SKEW_MAX_SECONDS", "30")),
            elastic_ready_timeout=int(os.getenv("VMRUN_ELASTIC_READY_TIMEOUT_SECONDS", "420")),
            elastic_canary_timeout=int(os.getenv("VMRUN_ELASTIC_CANARY_TIMEOUT_SECONDS", "360")),
            elastic_poll_attempts=int(os.getenv("VMRUN_ELASTIC_POLL_ATTEMPTS", "24")),
            elastic_agent_max_checkin_age=int(os.getenv("VMRUN_ELASTIC_AGENT_MAX_CHECKIN_AGE_SECONDS", "45")),
            guest_health_timeout=int(os.getenv("VMRUN_GUEST_HEALTH_TIMEOUT_SECONDS", "60")),
            execution_proof_timeout=int(os.getenv("VMRUN_EXECUTION_PROOF_TIMEOUT_SECONDS", "30")),
        )


class VMRun:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.start_process: subprocess.Popen[str] | None = None

    def _command(self, command: str, *args: str, guest: bool = False) -> list[str]:
        values = ["vmrun", "-T", "ws"]
        if self.settings.vm_password:
            values += ["-vp", self.settings.vm_password]
        if guest:
            values += ["-gu", self.settings.guest_user, "-gp", self.settings.guest_password]
        return values + [command, str(self.settings.vmx), *map(str, args)]

    def call(self, command: str, *args: str, guest: bool = False, check: bool = True, timeout: int = 60) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(
                self._command(command, *args, guest=guest),
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as error:
            raise PipelineError(f"vmrun {command} timed out after {timeout}s") from error
        if check and result.returncode:
            detail = (result.stderr or result.stdout).strip()
            raise PipelineError(f"vmrun {command} failed ({result.returncode}): {detail[:300]}")
        return result

    def snapshots(self) -> str:
        result = self.call("listSnapshots", "showTree", check=False)
        if result.returncode and not result.stdout.lstrip().startswith("Total snapshots:"):
            detail = (result.stderr or result.stdout).strip()
            raise PipelineError(f"vmrun listSnapshots failed ({result.returncode}): {detail[:300]}")
        return result.stdout

    def revert(self, snapshot: str) -> None:
        self.call("stop", "hard", check=False, timeout=30)
        self.call("revertToSnapshot", snapshot, timeout=180)
        try:
            self.start_process = subprocess.Popen(
                self._command("start", "nogui"),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
        except OSError as error:
            raise PipelineError(f"vmrun start nogui failed: {error}") from error

    def wait_for_tools(self) -> None:
        deadline = time.monotonic() + self.settings.tools_timeout
        last = ""
        while time.monotonic() < deadline:
            if self.start_process and (code := self.start_process.poll()) not in (None, 0):
                stdout, stderr = self.start_process.communicate()
                raise PipelineError(f"vmrun start nogui failed ({code}): {(stderr or stdout).strip()[:300]}")
            try:
                result = self.call("checkToolsState", check=False, timeout=15)
                tools_state = (result.stdout + result.stderr).strip()
                # Workstation reports "installed" for functional Tools in nogui mode.
                if tools_state.lower() in {"running", "installed"}:
                    probe_timeout = min(60, max(1, int(deadline - time.monotonic())))
                    probe = self.call(
                        "runProgramInGuest",
                        r"C:\Windows\System32\whoami.exe",
                        guest=True,
                        check=False,
                        timeout=probe_timeout,
                    )
                    if probe.returncode == 0:
                        return
                    last = f"Tools={tools_state}; guest probe={(probe.stderr or probe.stdout).strip()[:200]}"
                else:
                    last = tools_state
            except PipelineError as error:
                last = str(error)
            time.sleep(3)
        raise PipelineError(f"VMware guest operations did not become ready: {last[:300]}")

    def run_powershell(self, script: str) -> str:
        token = f"{os.getpid()}-{time.time_ns()}"
        guest_output = rf"C:\Windows\Temp\vmrun-powershell-{token}.txt"
        host_output = Path("/tmp") / f"vmrun-powershell-{token}.txt"
        wrapper = (
            f"$p='{guest_output}'; try {{ $v=& {{ {script} }} *>&1 | Out-String -Width 4096; "
            "$v | Set-Content -LiteralPath $p -Encoding UTF8 } catch { "
            "$_ | Out-String | Set-Content -LiteralPath $p -Encoding UTF8; exit 1 }"
        )
        encoded = base64.b64encode(wrapper.encode("utf-16le")).decode("ascii")
        output = ""
        try:
            result = self.call(
                "runProgramInGuest",
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                encoded,
                guest=True,
                check=False,
                timeout=45,
            )
            if self.exists(guest_output):
                self.copy_from_guest(guest_output, host_output)
                output = host_output.read_text(encoding="utf-8-sig").strip()
            if result.returncode:
                detail = output or (result.stderr or result.stdout).strip()
                raise PipelineError(f"Guest PowerShell failed ({result.returncode}): {detail[:300]}")
            return output
        finally:
            self.call("deleteFileInGuest", guest_output, guest=True, check=False)
            host_output.unlink(missing_ok=True)

    def create_directory(self, path: str) -> None:
        self.call("createDirectoryInGuest", path, guest=True)

    def copy_to_guest(self, source: Path, destination: str) -> None:
        self.call("CopyFileFromHostToGuest", str(source), destination, guest=True)

    def copy_from_guest(self, source: str, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        self.call("CopyFileFromGuestToHost", source, str(destination), guest=True)

    def rename_guest_file(self, source: str, destination: str) -> None:
        self.call("renameFileInGuest", source, destination, guest=True)

    def exists(self, path: str) -> bool:
        return self.call("fileExistsInGuest", path, guest=True, check=False).returncode == 0

    def launch(self, path: str, working_directory: str) -> None:
        quoted_path = path.replace("'", "''")
        quoted_directory = working_directory.replace("'", "''")
        script = f"Start-Process -FilePath '{quoted_path}' -WorkingDirectory '{quoted_directory}'"
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        self.call(
            "runProgramInGuest",
            "-noWait",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            encoded,
            guest=True,
        )

    def wait_for_execution_proof(self, path: str) -> dict[str, str]:
        interval = max(1, self.settings.poll_wait)
        attempts = max(1, (self.settings.execution_proof_timeout + interval - 1) // interval + 1)
        quoted = path.replace("'", "''")
        for attempt in range(attempts):
            output = self.run_powershell(
                f"if (Test-Path -LiteralPath '{quoted}') {{ Get-Content -LiteralPath '{quoted}' -Raw }}"
            ).strip()
            if output == "ALIVE":
                return {"status": "PASSED", "path": path, "value": output}
            if attempt + 1 < attempts:
                time.sleep(interval)
        raise ExecutionFailure(
            f"payload execution proof not observed at {path} within {self.settings.execution_proof_timeout}s"
        )


class CampaignState:
    def __init__(self, campaign_dir: Path):
        self.path = campaign_dir / "state.json"
        self.data = json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {"runs": {}}

    @staticmethod
    def key(engine: str, sha256: str) -> str:
        return f"{engine}:{sha256}"

    def completed(self, engine: str, sha256: str) -> bool:
        return self.data["runs"].get(self.key(engine, sha256), {}).get("status") == "COMPLETED"

    def save(self, engine: str, sha256: str, value: dict[str, Any]) -> None:
        self.data["runs"][self.key(engine, sha256)] = value
        atomic_json_write(self.path, self.data)


class HostServices:
    def active(self, engine: str) -> bool:
        units = SERVICE_UNITS.get(engine)
        if not units:
            return True
        return all(
            subprocess.run(["systemctl", "is-active", "--quiet", unit], check=False).returncode == 0
            for unit in units
        )

    def ensure(self, engine: str) -> bool:
        if engine not in SERVICE_UNITS or self.active(engine):
            return False
        result = subprocess.run(
            ["sudo", "-n", str(BASE_DIR / "manage-services.sh"), engine, "start"],
            capture_output=True,
            text=True,
        )
        if result.returncode:
            raise PipelineError(f"Could not start {engine} services: {(result.stderr or result.stdout).strip()[:300]}")
        return True

    def stop(self, engine: str) -> None:
        result = subprocess.run(
            ["sudo", "-n", str(BASE_DIR / "manage-services.sh"), engine, "stop"],
            capture_output=True,
            text=True,
        )
        if result.returncode:
            raise PipelineError(f"Could not stop {engine} services: {(result.stderr or result.stdout).strip()[:300]}")


class Collector:
    def __init__(self, settings: Settings):
        self.settings = settings

    def host_ready(self, engine: str, timeout: int = 90) -> None:
        if engine == "defender":
            return
        if engine == "elastic":
            url = os.getenv("ELASTICSEARCH_URL", "https://localhost:9201")
            auth = basic_auth("ES")
        else:
            url = os.getenv("WAZUH_INDEXER_URL", "https://127.0.0.1:9200")
            auth = basic_auth("WAZUH")
        deadline = time.monotonic() + timeout
        last_error = "not ready"
        while time.monotonic() < deadline:
            try:
                response = requests.get(f"{url.rstrip('/')}/_cluster/health", auth=auth, verify=tls_verify(), timeout=10)
                if response.status_code == 200 and response.json().get("status") != "red":
                    if engine == "elastic":
                        fleet_url = os.getenv("FLEET_SERVER_URL", "https://127.0.0.1:8220").rstrip("/")
                        fleet = requests.get(f"{fleet_url}/api/status", verify=tls_verify(), timeout=10)
                        fleet_status = fleet.json().get("status") if fleet.status_code == 200 else None
                        if fleet.status_code != 200 or fleet_status != "HEALTHY":
                            last_error = f"Fleet Server HTTP {fleet.status_code}, status={fleet_status or 'unknown'}"
                            time.sleep(3)
                            continue
                    else:
                        archives = requests.post(
                            f"{url.rstrip('/')}/wazuh-archives-*/_search", auth=auth,
                            verify=tls_verify(), json={"size": 0}, timeout=10,
                        )
                        if archives.status_code != 200 or archives.json().get("_shards", {}).get("total") == 0:
                            raise PipelineError("Wazuh archives index is missing or unreadable; enable logall_json and Filebeat archives indexing")
                    return
                last_error = f"HTTP {response.status_code}, cluster={response.json().get('status')}"
            except requests.RequestException as error:
                last_error = str(error)
            time.sleep(3)
        raise PipelineError(f"{engine} backend not ready after {timeout}s: {last_error}")

    def collect(self, engine: str, artifacts: list[dict[str, Any]], started: str, ended: str) -> dict[str, Any]:
        start = datetime.fromisoformat(started.replace("Z", "+00:00")) - timedelta(seconds=30)
        late_window = max(90, self.settings.elastic_poll_attempts * self.settings.poll_wait) if engine == "elastic" else 90
        end = datetime.fromisoformat(ended.replace("Z", "+00:00")) + timedelta(seconds=late_window)
        if engine == "elastic":
            return self._poll_elastic(artifacts, start.isoformat(), end.isoformat())
        if engine == "wazuh":
            return self._poll_wazuh(artifacts, start.isoformat(), end.isoformat())
        raise PipelineError(f"Unsupported collector: {engine}")

    def wait_for_sample_telemetry(self, engine: str, guest_file: str, sha256: str, started: str) -> dict[str, Any]:
        start = (datetime.fromisoformat(started.replace("Z", "+00:00")) - timedelta(seconds=max(30, self.settings.clock_skew_max))).isoformat()
        if engine == "elastic":
            url = os.getenv("ELASTICSEARCH_URL", "https://localhost:9201").rstrip("/") + "/logs-endpoint.events.process-*/_search"
            auth = basic_auth("ES")
            should = [
                {"term": {"process.hash.sha256": {"value": sha256, "case_insensitive": True}}},
                {"term": {"process.executable": {"value": guest_file, "case_insensitive": True}}},
                {"term": {"process.parent.executable": {"value": guest_file, "case_insensitive": True}}},
            ]
            filters = [{"range": {"@timestamp": {"gte": start}}}]
            request = requests.get
            attempts = self.settings.elastic_poll_attempts
        elif engine == "wazuh":
            url = os.getenv("WAZUH_INDEXER_URL", "https://127.0.0.1:9200").rstrip("/") + "/wazuh-archives-*/_search"
            auth = basic_auth("WAZUH")
            should = [{"wildcard": {"data.win.eventdata.hashes": f"*{sha256.upper()}*"}}]
            filters = [{"range": {"timestamp": {"gte": start}}}, {"term": {"data.win.system.eventID": "1"}}]
            if os.getenv("WAZUH_AGENT_ID"):
                filters.append({"term": {"agent.id": os.environ["WAZUH_AGENT_ID"]}})
            request = requests.post
            attempts = self.settings.poll_attempts
        else:
            raise PipelineError(f"Unsupported telemetry source: {engine}")
        query = {"query": {"bool": {"should": should, "minimum_should_match": 1, "filter": filters}},
                 "sort": [{"@timestamp": "asc"}], "size": 1}
        deadline = time.monotonic() + max(90, attempts * self.settings.poll_wait)
        while True:
            response = request(url, auth=auth, verify=tls_verify(), json=query, timeout=15)
            if response.status_code != 200:
                hint = " (enable Wazuh JSON archives and Filebeat archives indexing)" if engine == "wazuh" and response.status_code == 404 else ""
                raise PipelineError(f"{engine} telemetry query failed: HTTP {response.status_code}{hint}")
            payload = response.json()
            if engine == "wazuh" and payload.get("_shards", {}).get("total") == 0:
                raise PipelineError("Wazuh archives index is missing; enable logall_json and Filebeat archives indexing")
            hits = payload.get("hits", {}).get("hits", [])
            if hits:
                source = hits[0].get("_source", {})
                process = source.get("process", {}) if engine == "elastic" else {}
                parent = process.get("parent", {})
                child_evidence = (engine == "elastic" and
                                  str(parent.get("executable", "")).casefold() == guest_file.casefold() and
                                  str(process.get("executable", "")).casefold() != guest_file.casefold())
                return {"status": "OBSERVED", "index": hits[0].get("_index"),
                        "event_id": source.get("event", {}).get("id") if engine == "elastic" else source.get("data", {}).get("win", {}).get("system", {}).get("eventID"),
                        "timestamp": source.get("@timestamp") or source.get("timestamp"),
                        "process_guid": source.get("data", {}).get("win", {}).get("eventdata", {}).get("processGuid") if engine == "wazuh" else (parent if child_evidence else process).get("entity_id"),
                        "evidence_type": "child_process" if child_evidence else "sample_process"}
            if time.monotonic() >= deadline:
                raise PipelineError(f"{engine} sample process telemetry not observed for SHA256 {sha256} within {int(max(90, attempts * self.settings.poll_wait))}s")
            time.sleep(self.settings.poll_wait)

    @staticmethod
    def _matching_artifacts(value: dict[str, Any], artifacts: list[dict[str, Any]]) -> list[dict[str, str]]:
        text = json.dumps(value, ensure_ascii=False).casefold()
        matches = []
        for artifact in artifacts:
            reasons = [field for field in ("sha256", "guest_path", "name")
                       if artifact.get(field) and str(artifact[field]).casefold() in text]
            if reasons:
                matches.append({"name": artifact["name"], "match_reason": reasons[0]})
        return matches

    def wait_for_companion_telemetry(self, engine: str, artifacts: list[dict[str, Any]], started: str) -> list[dict[str, Any]]:
        companions = [item for item in artifacts if item["role"] == "companion" and item["name"].lower().endswith(".dll")]
        if not companions:
            return []
        start = (datetime.fromisoformat(started.replace("Z", "+00:00")) -
                 timedelta(seconds=max(30, self.settings.clock_skew_max))).isoformat()
        if engine == "elastic":
            url = os.getenv("ELASTICSEARCH_URL", "https://localhost:9201").rstrip("/") + "/logs-endpoint.events.library-*/_search"
            auth = basic_auth("ES")
            should = []
            for artifact in companions:
                should.extend([
                    {"term": {"dll.hash.sha256": artifact["sha256"]}},
                    {"term": {"file.hash.sha256": artifact["sha256"]}},
                    {"wildcard": {"dll.path": f"*{artifact['name']}*"}},
                    {"wildcard": {"file.path": f"*{artifact['name']}*"}},
                ])
            filters = [{"range": {"@timestamp": {"gte": start}}}]
            request = requests.get
            attempts = self.settings.elastic_poll_attempts
        elif engine == "wazuh":
            url = os.getenv("WAZUH_INDEXER_URL", "https://127.0.0.1:9200").rstrip("/") + "/wazuh-archives-*/_search"
            auth = basic_auth("WAZUH")
            should = []
            for artifact in companions:
                should.extend([
                    {"wildcard": {"data.win.eventdata.hashes": f"*{artifact['sha256'].upper()}*"}},
                    {"wildcard": {"data.win.eventdata.imageLoaded": f"*{artifact['name']}*"}},
                ])
            filters = [{"range": {"timestamp": {"gte": start}}}, {"term": {"data.win.system.eventID": "7"}}]
            if os.getenv("WAZUH_AGENT_ID"):
                filters.append({"term": {"agent.id": os.environ["WAZUH_AGENT_ID"]}})
            request = requests.post
            attempts = self.settings.poll_attempts
        else:
            raise PipelineError(f"Unsupported telemetry source: {engine}")
        query = {"query": {"bool": {"should": should, "minimum_should_match": 1, "filter": filters}},
                 "sort": [{"@timestamp": "asc"}], "size": 100}
        observed: dict[str, dict[str, Any]] = {}
        deadline = time.monotonic() + max(90, attempts * self.settings.poll_wait)
        while True:
            response = request(url, auth=auth, verify=tls_verify(), json=query, timeout=15)
            if response.status_code != 200:
                raise PipelineError(f"{engine} DLL-load telemetry query failed: HTTP {response.status_code}")
            for hit in response.json().get("hits", {}).get("hits", []):
                source = hit.get("_source", {})
                for match in self._matching_artifacts(source, companions):
                    observed.setdefault(match["name"], {
                        "name": match["name"], "status": "LOADED", "index": hit.get("_index"),
                        "timestamp": source.get("@timestamp") or source.get("timestamp"),
                        "event_id": source.get("event", {}).get("id") if engine == "elastic" else "7",
                        "match_reason": match["match_reason"],
                    })
            if len(observed) == len(companions):
                return [observed[item["name"]] for item in companions]
            if time.monotonic() >= deadline:
                missing = ", ".join(item["name"] for item in companions if item["name"] not in observed)
                raise ExecutionFailure(f"{engine} DLL-load telemetry not observed for: {missing}")
            time.sleep(self.settings.poll_wait)

    def elastic_agent(self, hostname: str) -> dict[str, Any] | None:
        url = os.getenv("KIBANA_URL", "http://127.0.0.1:5601").rstrip("/")
        response = requests.get(
            f"{url}/api/fleet/agents",
            params={"perPage": 100},
            headers={"kbn-xsrf": "vmrun-pipeline"},
            auth=basic_auth("ES"),
            verify=tls_verify(),
            timeout=15,
        )
        if response.status_code != 200:
            return None
        agents = response.json()
        for agent in agents.get("items") or agents.get("list", []):
            agent_hostname = str((agent.get("local_metadata") or {}).get("host", {}).get("hostname", ""))
            if agent_hostname.lower() == hostname.lower():
                return agent
        return None

    def wait_for_elastic_canary(self, hostname: str, marker: str, started: str, timeout: int) -> dict[str, Any]:
        url = os.getenv("ELASTICSEARCH_URL", "https://localhost:9201").rstrip("/")
        start = datetime.fromisoformat(started.replace("Z", "+00:00")) - timedelta(seconds=30)
        query = {
            "query": {"bool": {
                "filter": [
                    {"term": {"host.name": {"value": hostname, "case_insensitive": True}}},
                    {"range": {"@timestamp": {"gte": start.isoformat()}}},
                ],
                "must": [{"wildcard": {"process.command_line": f"*{marker}*"}}],
            }},
            "size": 1,
            "sort": [{"@timestamp": "asc"}],
        }
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            response = requests.get(
                f"{url}/logs-endpoint.events.process-*/_search",
                auth=basic_auth("ES"), verify=tls_verify(), json=query, timeout=15,
            )
            if response.status_code == 200:
                hits = response.json().get("hits", {}).get("hits", [])
                if hits:
                    event = hits[0].get("_source", {})
                    return {"marker": marker, "event_id": event.get("event", {}).get("id"),
                            "timestamp": event.get("@timestamp")}
            time.sleep(self.settings.poll_wait)
        raise PipelineError(f"Elastic telemetry canary was not observed after {timeout}s: {marker}")

    def _poll_elastic(self, artifacts: list[dict[str, Any]], start: str, end: str) -> dict[str, Any]:
        url = os.getenv("ELASTICSEARCH_URL", "https://localhost:9201").rstrip("/")
        should = []
        for artifact in artifacts:
            should.extend([
                {"term": {"file.hash.sha256": artifact["sha256"]}},
                {"term": {"process.hash.sha256": artifact["sha256"]}},
                {"term": {"dll.hash.sha256": artifact["sha256"]}},
                {"wildcard": {"file.path": f"*{artifact['name']}*"}},
                {"wildcard": {"process.name": f"*{artifact['name']}*"}},
                {"wildcard": {"process.executable": f"*{artifact['name']}*"}},
                {"wildcard": {"dll.path": f"*{artifact['name']}*"}},
            ])
        query = {"query": {"bool": {"should": should, "minimum_should_match": 1,
                 "filter": [{"range": {"@timestamp": {"gte": start, "lte": end}}}]}},
                 "sort": [{"@timestamp": "asc"}], "size": 100}
        seen: dict[str, dict[str, Any]] = {}
        stopped_early = False
        for attempt in range(self.settings.elastic_poll_attempts):
            for index in ("logs-endpoint.alerts-*", ".alerts-security.alerts-default"):
                response = requests.get(f"{url}/{index}/_search", auth=basic_auth("ES"), verify=tls_verify(), json=query, timeout=15)
                if response.status_code != 200:
                    raise PipelineError(f"Elastic alert query failed for {index}: HTTP {response.status_code}")
                for hit in response.json().get("hits", {}).get("hits", []):
                    seen[hit.get("_id", str(hit))] = hit.get("_source", {})
            if any(self._elastic_event_code(item) == "behavior" for item in seen.values()):
                stopped_early = attempt + 1 < self.settings.elastic_poll_attempts
                break
            if attempt + 1 < self.settings.elastic_poll_attempts:
                time.sleep(self.settings.poll_wait)
        alerts = [{**item, "matched_artifacts": self._matching_artifacts(item, artifacts)} for item in seen.values()]
        unique_alerts = self._unique_elastic_alerts(alerts)
        codes = [self._elastic_event_code(item) for item in unique_alerts]
        return {"status": "DETECTED" if "behavior" in codes else "NO_ALERT", "raw_alerts": alerts, "unique_alerts": unique_alerts,
                "raw_alert_count": len(alerts), "unique_alert_count": len(unique_alerts),
                "behavior_detected": "behavior" in codes, "behavior_alert_count": codes.count("behavior"),
                "file_detected": "malicious_file" in codes, "file_alert_count": codes.count("malicious_file"),
                "collection_ended_early": stopped_early}

    @staticmethod
    def _elastic_event_code(alert: dict[str, Any]) -> str:
        return str(alert.get("event", {}).get("code") or alert.get("kibana.alert.original_event", {}).get("code") or "")

    @classmethod
    def _unique_elastic_alerts(cls, alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        unique: dict[str, dict[str, Any]] = {}
        for alert in alerts:
            event = alert.get("event") or {}
            original = alert.get("kibana.alert.original_event") or {}
            event_id = event.get("id") or original.get("id")
            process = alert.get("process") or {}
            key = str(event_id) if event_id else json.dumps({
                "code": cls._elastic_event_code(alert), "timestamp": alert.get("@timestamp"),
                "process": process.get("entity_id") or process.get("hash", {}).get("sha256"),
                "message": alert.get("message"),
            }, sort_keys=True)
            unique.setdefault(key, alert)
        return list(unique.values())

    def _poll_wazuh(self, artifacts: list[dict[str, Any]], start: str, end: str) -> dict[str, Any]:
        url = os.getenv("WAZUH_INDEXER_URL", "https://127.0.0.1:9200").rstrip("/")
        agent_id = os.getenv("WAZUH_AGENT_ID")
        fields = ["image", "imageLoaded", "targetFilename", "parentImage", "newProcessName", "parentProcessName", "sourceImage", "targetImage"]
        aliases = {artifact["name"] for artifact in artifacts}
        should = [
            {"wildcard": {f"data.win.eventdata.{field}": f"*{alias}*"}}
            for field in fields for alias in aliases
        ]
        should += [{"match_phrase": {"full_log": alias}} for alias in aliases]
        should += [{"wildcard": {"data.win.eventdata.hashes": f"*{artifact['sha256'].upper()}*"}}
                   for artifact in artifacts]
        must = [{"bool": {"should": should, "minimum_should_match": 1}}]
        if agent_id:
            must.insert(0, {"term": {"agent.id": agent_id}})
        query = {"query": {"bool": {"must": must, "filter": [{"range": {"@timestamp": {"gte": start, "lte": end}}}]}},
                 "sort": [{"@timestamp": "asc"}], "size": 100}
        seen: dict[str, dict[str, Any]] = {}
        for _ in range(self.settings.poll_attempts):
            response = requests.post(f"{url}/wazuh-alerts-4.x-*/_search", auth=basic_auth("WAZUH"), verify=tls_verify(), json=query, timeout=15)
            if response.status_code != 200:
                raise PipelineError(f"Wazuh alert query failed: HTTP {response.status_code}")
            for hit in response.json().get("hits", {}).get("hits", []):
                seen[hit.get("_id", str(hit))] = hit.get("_source", {})
            time.sleep(self.settings.poll_wait)
        alerts = [{**item, "matched_artifacts": self._matching_artifacts(item, artifacts)} for item in seen.values()]
        suspicious = [item for item in alerts if int(item.get("rule", {}).get("level", 0)) >= 7]
        return {"status": "DETECTED" if suspicious else "NO_ALERT", "raw_alerts": alerts,
                "detected": bool(suspicious), "suspicious_alert_count": len(suspicious), "total_alert_count": len(alerts)}


def json_from_output(text: str) -> dict[str, Any]:
    for line in reversed(text.splitlines()):
        try:
            value = json.loads(line)
            if isinstance(value, dict):
                return value
        except json.JSONDecodeError:
            pass
    raise PipelineError(f"Guest PowerShell did not return JSON: {text[-300:]}")


def json_document_from_output(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text.lstrip("\ufeff").strip())
        if isinstance(value, dict):
            return value
    except json.JSONDecodeError:
        pass
    return json_from_output(text)


class Runner:
    def __init__(self, settings: Settings, campaign: str):
        self.settings = settings
        self.campaign = campaign
        self.campaign_dir = settings.output_dir / campaign
        self.vmrun = VMRun(settings)
        self.collector = Collector(settings)
        self.services = HostServices()
        self.state = CampaignState(self.campaign_dir)

    def lock(self):
        self.campaign_dir.mkdir(parents=True, exist_ok=True)
        handle = (self.campaign_dir / ".lock").open("w", encoding="utf-8")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            handle.close()
            raise PipelineError(f"Campaign is already running: {self.campaign}")
        return handle

    @staticmethod
    def _phase(message: str) -> None:
        print(f"  -> {message}", flush=True)

    @staticmethod
    def _guest_summary(health: dict[str, Any]) -> str:
        service_items = health.get("services") or []
        if isinstance(service_items, dict):
            service_items = [service_items]
        services = ", ".join(f"{item['Name']}={item['Status']}" for item in service_items)
        defender = health.get("defender") or {}
        defender_state = "ON" if defender.get("RealTimeProtectionEnabled") else "OFF"
        image_load = "; Sysmon ImageLoad=ON" if health.get("sysmon_image_load_enabled") else ""
        return f"{services}; Defender={defender_state}{image_load}; clock skew={health['clock_skew_seconds']}s"

    @staticmethod
    def _print_result(report: dict[str, Any], elapsed: float) -> None:
        engine = report["engine"]
        result = report.get(engine) or {}
        verdict = report.get("verdict", "N/A") if report["status"] == "COMPLETED" else report["status"]
        print("-" * 78)
        print(f"RESULT  {verdict:<14} engine={engine}  elapsed={elapsed:.1f}s")
        if report["status"] != "COMPLETED":
            print(f"  Error: {report.get('error', 'unknown infrastructure failure')}")
        elif verdict == "NOT_EXECUTED":
            print("  Stage: STATIC; sample was not launched, so behavior was not evaluated")
        elif engine == "wazuh":
            if report.get("telemetry"):
                print(f"  Telemetry: sample process observed at {report['telemetry'].get('timestamp', '-')}")
            alerts = result.get("raw_alerts") or []
            print(f"  Alerts: {result.get('suspicious_alert_count', 0)} suspicious / {result.get('total_alert_count', 0)} correlated")
            if alerts:
                alert = alerts[0]
                rule = alert.get("rule") or {}
                event = alert.get("data", {}).get("win", {}).get("system", {}).get("eventID", "-")
                mitre = ",".join(rule.get("mitre", {}).get("id", [])) or "-"
                print(f"  Evidence: rule={rule.get('id', '-')} level={rule.get('level', '-')} sysmon_event={event} mitre={mitre}")
        elif engine == "elastic":
            if report.get("telemetry"):
                kind = "child process" if report["telemetry"].get("evidence_type") == "child_process" else "sample process"
                print(f"  Telemetry: {kind} observed at {report['telemetry'].get('timestamp', '-')}")
            print(f"  Alerts: {result.get('raw_alert_count', len(result.get('raw_alerts') or []))} raw / {result.get('unique_alert_count', len(result.get('raw_alerts') or []))} unique")
            count = result.get("behavior_alert_count", 0)
            count_label = f">={count}" if result.get("collection_ended_early") else str(count)
            print(f"  Behavior: {count_label} detected; file/ML: {result.get('file_alert_count', 0)} ignored")
        else:
            print(f"  Stage: {report.get('stage', 'RUNTIME')}")
            print(f"  Evidence: defender_events={len(result.get('defender_events') or [])} threats={len(result.get('threat_detections') or [])}")
        loaded = [item["name"] for item in report.get("artifacts") or [] if item.get("telemetry") == "LOADED"]
        if loaded:
            print(f"  DLL telemetry: {', '.join(loaded)} loaded")
        if report.get("execution_proof"):
            print(f"  Execution proof: {report['execution_proof']['status']} ({report['execution_proof']['path']})")
        if result.get("threat_query_error"):
            print(f"  Threat query unavailable: {result['threat_query_error'][:160]}")
        print("=" * 78, flush=True)

    @staticmethod
    def _print_doctor_result(engine: str, snapshot: str, check: dict[str, Any], elapsed: float) -> None:
        print("-" * 78)
        state = "READY" if check["ready"] else "NOT READY"
        print(f"DOCTOR RESULT  {state:<9} engine={engine}  snapshot={snapshot}  elapsed={elapsed:.1f}s")
        if check["ready"]:
            print(f'  Guest: {Runner._guest_summary(check["guest"])}')
        else:
            print(f'  Reason: {check["reason"]}')
        print("=" * 78, flush=True)

    def _write_summary(self, jobs: list[tuple[str, Path, str, str]], skipped: int, started_at: str) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        for engine, sample, digest, package_digest in jobs:
            metadata = sample_metadata(sample)
            checkpoint = self.state.data["runs"].get(self.state.key(engine, package_digest), {})
            report_path = self.campaign_dir / checkpoint.get("report", "")
            report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.is_file() else {}
            engine_result = report.get(engine) or {}
            raw_alerts = len(engine_result.get("raw_alerts") or [])
            alerts = engine_result.get("behavior_alert_count", 0) if engine == "elastic" else raw_alerts
            evidence = len(engine_result.get("defender_events") or []) + len(engine_result.get("threat_detections") or [])
            matched_artifacts = list(engine_result.get("matched_artifacts") or [])
            matched_artifacts.extend(
                match for alert in engine_result.get("raw_alerts") or []
                for match in alert.get("matched_artifacts") or []
            )
            rows.append({
                "sample": sample.name,
                "sha256": digest,
                "package_sha256": package_digest,
                "artifact_count": len(report.get("artifacts") or sample_artifacts(sample, digest)),
                "dll_telemetry": sum(item.get("telemetry") == "LOADED" for item in report.get("artifacts") or []),
                "detected_artifacts": ",".join(sorted({match["name"] for match in matched_artifacts})),
                "technique": metadata.get("technique", ""),
                "fidelity": metadata.get("fidelity", ""),
                "execution_proof": (report.get("execution_proof") or {}).get("status", "NOT_REQUIRED"),
                "engine": engine,
                "status": checkpoint.get("status", "MISSING"),
                "verdict": report.get("verdict", "N/A"),
                "stage": report.get("stage", "RUNTIME"),
                "alerts": alerts if engine != "defender" else evidence,
                "raw_alerts": raw_alerts if engine != "defender" else evidence,
                "unique_alerts": engine_result.get("unique_alert_count", raw_alerts) if engine == "elastic" else raw_alerts,
                "report": checkpoint.get("report", ""),
            })
        completed = sum(row["status"] == "COMPLETED" for row in rows)
        failed = len(rows) - completed
        engines = list(dict.fromkeys(engine for engine, _sample, _digest, _package in jobs))
        detections = {engine: sum(row["engine"] == engine and row["verdict"] == "DETECTED" for row in rows) for engine in engines}
        summary = {
            "campaign": self.campaign,
            "started_at": started_at,
            "completed_at": iso_now(),
            "jobs": {"total": len(rows), "completed": completed, "skipped": skipped, "failed": failed},
            "detections": detections,
            "rows": rows,
        }
        atomic_json_write(self.campaign_dir / "summary.json", summary)
        csv_path = self.campaign_dir / "summary.csv"
        with csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]) if rows else ["sample", "engine", "status", "verdict"])
            writer.writeheader()
            writer.writerows(rows)
        return summary

    def _print_campaign_summary(self, summary: dict[str, Any], elapsed: float) -> None:
        jobs = summary["jobs"]
        detected = " | ".join(f"{engine}={count}" for engine, count in summary["detections"].items())
        print("=" * 78)
        print(f"CAMPAIGN COMPLETED  {self.campaign}  elapsed={elapsed:.1f}s")
        print(f"  Jobs: {jobs['completed']} completed | {jobs['skipped']} skipped | {jobs['failed']} failed")
        print(f"  Detections: {detected}")
        print(f"  Reports: {self.campaign_dir / 'summary.json'}")
        print("  VM: left running (use vmrun stop when finished)")
        print("=" * 78, flush=True)

    def doctor(self, engines: list[str]) -> dict[str, Any]:
        snapshots = self.vmrun.snapshots()
        result: dict[str, Any] = {"checked_at": iso_now(), "engines": {}}
        for engine in engines:
            snapshot = SNAPSHOTS[engine]
            started = time.monotonic()
            print("=" * 78)
            print(f"DOCTOR  engine={engine.upper()}  snapshot={snapshot}")
            print("-" * 78, flush=True)
            if snapshot not in snapshots:
                result["engines"][engine] = {"ready": False, "reason": f"Snapshot not found: {snapshot}"}
                self._print_doctor_result(engine, snapshot, result["engines"][engine], time.monotonic() - started)
                continue
            started_services = False
            try:
                self._phase("Checking host backend")
                started_services = self.services.ensure(engine)
                self.collector.host_ready(engine)
                self._phase("Host backend ready")
                self._phase(f"Reverting VM to snapshot '{snapshot}'")
                self.vmrun.revert(snapshot)
                self.vmrun.wait_for_tools()
                self._phase("VMware Tools ready")
                self._phase("Checking guest services and monitoring")
                guest = self._wait_for_guest_health(engine)
                self._phase("Guest ready: " + self._guest_summary(guest))
                check: dict[str, Any] = {"ready": True, "snapshot": snapshot, "guest": guest}
                if engine == "elastic":
                    self._phase("Waiting for Elastic Agent, Endpoint, and telemetry canary")
                    check["elastic_readiness"] = self._wait_for_elastic_readiness(
                        f"{self.campaign}-doctor-elastic", guest,
                    )
                result["engines"][engine] = check
            except (PipelineError, requests.RequestException) as error:
                result["engines"][engine] = {"ready": False, "snapshot": snapshot, "reason": str(error)}
            finally:
                if started_services:
                    self.services.stop(engine)
            self._print_doctor_result(engine, snapshot, result["engines"][engine], time.monotonic() - started)
        atomic_json_write(self.campaign_dir / "doctor.json", result)
        return result

    def _guest_health(self, engine: str, require_image_load: bool = False) -> dict[str, Any]:
        service_names = {"elastic": ["Elastic Agent"], "wazuh": ["WazuhSvc", "Sysmon64"], "defender": ["WinDefend"]}[engine]
        optional_names = ["Sysmon64"] if engine == "defender" else []
        probed_names = service_names + optional_names
        service_literals = ",".join("'" + name + "'" for name in probed_names)
        defender = "try { Get-MpComputerStatus -ErrorAction Stop | Select-Object RealTimeProtectionEnabled,BehaviorMonitorEnabled,AntivirusSignatureVersion,EngineVersion } catch { $null }"
        wazuh_setup = "$w=$null; $i=$null; "
        if engine == "wazuh":
            wazuh_setup = "$p='C:\\Program Files (x86)\\ossec-agent\\ossec.conf'; $w=(Test-Path $p) -and [bool](Select-String -Path $p -SimpleMatch 'Microsoft-Windows-Sysmon/Operational' -Quiet); $i=$null; "
            if require_image_load:
                wazuh_setup += "$sp=(Get-CimInstance Win32_Service -Filter \"Name='Sysmon64'\").PathName.Trim('\"'); $sc=(& $sp -c 2>&1 | Out-String); $i=[bool]($sc -match 'Image loading:\\s+enabled'); "
        script = (
            "$services=@(" + service_literals + ") | ForEach-Object { $s=Get-Service -Name $_ -ErrorAction SilentlyContinue; "
            "if($s){[PSCustomObject]@{Name=$s.Name;Status=$s.Status.ToString()}} }; "
            "$d=" + defender + "; "
            + wazuh_setup +
            "$now=[DateTime]::UtcNow.ToString('o'); $hostName=$env:COMPUTERNAME; "
            "[PSCustomObject]@{services=$services;defender=$d;wazuh_sysmon_configured=$w;sysmon_image_load_enabled=$i;hostname=$hostName;utc=$now}|ConvertTo-Json -Compress -Depth 4"
        )
        result = json_from_output(self.vmrun.run_powershell(script))
        services = result.get("services") or []
        services = [services] if isinstance(services, dict) else services
        by_name = {item.get("Name"): item.get("Status") for item in services}
        missing = [name for name in service_names if name not in by_name]
        if missing:
            raise PipelineError("Guest service probe is missing: " + ", ".join(missing))
        stopped = [name for name in service_names if by_name.get(name) != "Running"]
        if stopped:
            raise PipelineError(f"Guest services not running: {', '.join(stopped)}")
        if optional_names:
            result["optional_services"] = {name: by_name.get(name, "NOT_INSTALLED") for name in optional_names}
        if engine == "defender":
            status = result.get("defender") or {}
            if not status.get("RealTimeProtectionEnabled") or not status.get("BehaviorMonitorEnabled"):
                raise PipelineError("Windows Defender real-time or behavior monitoring is disabled")
        else:
            status = result.get("defender") or {}
            if status.get("RealTimeProtectionEnabled") or status.get("BehaviorMonitorEnabled"):
                raise PipelineError(f"Windows Defender is enabled in the {engine} snapshot and would contaminate results")
        if engine == "wazuh" and not result.get("wazuh_sysmon_configured"):
            raise PipelineError("Wazuh Agent is not subscribed to Microsoft-Windows-Sysmon/Operational")
        if engine == "wazuh" and require_image_load and not result.get("sysmon_image_load_enabled"):
            raise PipelineError("Sysmon ImageLoad is disabled; DLL packages require Event ID 7 telemetry")
        guest_time = datetime.fromisoformat(result["utc"].replace("Z", "+00:00"))
        skew = abs((utcnow() - guest_time).total_seconds())
        if skew > self.settings.clock_skew_max:
            raise PipelineError(f"Guest clock skew is {skew:.1f}s (limit {self.settings.clock_skew_max}s)")
        result["clock_skew_seconds"] = round(skew, 3)
        return result

    def _wait_for_guest_health(self, engine: str, require_image_load: bool = False) -> dict[str, Any]:
        deadline = time.monotonic() + self.settings.guest_health_timeout
        last_error: PipelineError | None = None
        while time.monotonic() < deadline:
            try:
                return self._guest_health(engine, require_image_load=require_image_load)
            except PipelineError as error:
                transient = str(error).startswith(("Guest service probe is missing:", "Guest services not running:"))
                if not transient:
                    raise
                last_error = error
                self._phase("Guest services are still starting; retrying")
                time.sleep(3)
        raise last_error or PipelineError("Guest health check timed out")

    def _elastic_endpoint_status(self) -> dict[str, Any]:
        output = self.vmrun.run_powershell(
            "& 'C:\\Program Files\\Elastic\\Agent\\elastic-agent.exe' status --output json"
        )
        status = json_document_from_output(output)
        components = status.get("components") or []
        endpoint_items = [
            item for component in components if component.get("id") == "endpoint"
            for item in [component, *(component.get("units") or [])]
        ]
        revisions = [
            int(match.group(1)) for item in endpoint_items
            if (match := re.search(r"Agent policy rev\. (\d+)\.", str(item.get("message", ""))))
        ]
        healthy = status.get("state") == 2 and bool(revisions) and all(item.get("state") == 2 for item in endpoint_items)
        return {"healthy": healthy, "agent_state": status.get("state"), "agent_message": status.get("message"),
                "agent_policy_revision": revisions[0] if revisions and len(set(revisions)) == 1 else None,
                "endpoint": [{"id": item.get("id"), "state": item.get("state"), "message": item.get("message")} for item in endpoint_items]}

    def _wait_for_elastic_readiness(self, run_id: str, guest: dict[str, Any]) -> dict[str, Any]:
        hostname = str(guest.get("hostname") or "")
        if not hostname:
            raise PipelineError("Elastic guest health did not return hostname")
        deadline = time.monotonic() + self.settings.elastic_ready_timeout
        last = "not ready"
        while time.monotonic() < deadline:
            endpoint = self._elastic_endpoint_status()
            fleet_agent = self.collector.elastic_agent(hostname)
            last_checkin = str((fleet_agent or {}).get("last_checkin") or "")
            fresh = False
            if last_checkin:
                try:
                    checkin = datetime.fromisoformat(last_checkin.replace("Z", "+00:00"))
                    fresh = abs((utcnow() - checkin).total_seconds()) <= self.settings.elastic_agent_max_checkin_age
                except ValueError:
                    pass
            fleet_revision = (fleet_agent or {}).get("policy_revision")
            if (endpoint["healthy"] and fleet_revision is not None
                    and str(endpoint["agent_policy_revision"]) == str(fleet_revision)
                    and (fleet_agent or {}).get("status") in {"online", "degraded"} and fresh):
                marker = f"vmrun-canary-{run_id}-{time.time_ns()}"
                self._phase("Elastic Endpoint policy ready; sending telemetry canary")
                canary_started = iso_now()
                canary_deadline = min(deadline, time.monotonic() + self.settings.elastic_canary_timeout)
                while time.monotonic() < canary_deadline:
                    self.vmrun.run_powershell(f'& $env:ComSpec /d /c "echo {marker} >NUL"')
                    remaining = max(1, int(canary_deadline - time.monotonic()))
                    try:
                        canary = self.collector.wait_for_elastic_canary(
                            hostname, marker, canary_started, min(30, remaining),
                        )
                        return {"hostname": hostname, "fleet_agent_id": fleet_agent.get("id"),
                                "fleet_status": fleet_agent.get("status"), "last_checkin": last_checkin,
                                "endpoint": endpoint, "canary": canary}
                    except PipelineError:
                        if time.monotonic() < canary_deadline:
                            self._phase("Elastic telemetry canary not indexed yet; retrying")
                raise PipelineError(f"Elastic telemetry canary was not observed after {self.settings.elastic_canary_timeout}s: {marker}")
            fleet_state = (fleet_agent or {}).get("status", "missing")
            last = (f"Fleet={fleet_state}, checkin={last_checkin or 'missing'}, policy={fleet_revision}, "
                    f"Endpoint policy={endpoint['agent_policy_revision']}, state={endpoint['agent_message'] or endpoint['agent_state']}")
            time.sleep(self.settings.poll_wait)
        raise PipelineError(f"Elastic readiness gate timed out after {self.settings.elastic_ready_timeout}s: {last}")

    def run(self, samples: list[Path], engines: list[str], shuffle_seed: int | None) -> None:
        samples = list(samples)
        failures: list[str] = []
        if shuffle_seed is not None:
            random.Random(shuffle_seed).shuffle(samples)
        packages = [(sample, sha256_file(sample)) for sample in samples]
        packages = [(sample, digest, sample_package_sha256(sample, digest)) for sample, digest in packages]
        jobs = [(engine, sample, digest, package_digest)
                for engine in engines for sample, digest, package_digest in packages]
        skipped = sum(self.state.completed(engine, package_digest)
                      for engine, _sample, _digest, package_digest in jobs)
        started_at = iso_now()
        campaign_started = time.monotonic()
        manifest_path = self.campaign_dir / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else {
            "campaign": self.campaign,
            "created_at": started_at,
        }
        campaign_samples = []
        for path, digest, package_digest in packages:
            metadata = sample_metadata(path)
            campaign_samples.append({"path": str(path), "sha256": digest, "package_sha256": package_digest,
                                     "artifacts": [{"role": item["role"], "name": item["name"], "sha256": item["sha256"]}
                                                   for item in sample_artifacts(path, digest)], **{
                key: metadata[key] for key in ("technique", "fidelity") if key in metadata
            }})
        manifest.update({"engines": engines, "shuffle_seed": shuffle_seed,
                         "samples": campaign_samples,
                         "last_started_at": started_at})
        manifest.setdefault("run_history", []).append({"started_at": started_at, "jobs": len(jobs), "resumed_jobs": skipped})
        atomic_json_write(manifest_path, manifest)
        print("=" * 78)
        print(f"CAMPAIGN  {self.campaign}  jobs={len(jobs)}  resumed={skipped}")
        print("=" * 78, flush=True)
        for engine_index, engine in enumerate(engines):
            started_services = self.services.ensure(engine)
            try:
                self.collector.host_ready(engine)
                for sample_index, (sample, digest, package_digest) in enumerate(packages, start=1):
                    job_number = engine_index * len(samples) + sample_index
                    if self.state.completed(engine, package_digest):
                        print(f"[{job_number:02d}/{len(jobs)}] SKIP   engine={engine} sample={sample.name} already completed")
                        continue
                    print("=" * 78)
                    print(f"RUN [{job_number:02d}/{len(jobs)}]  engine={engine.upper()}  snapshot={SNAPSHOTS[engine]}")
                    print(f"  Sample: {sample.name}")
                    metadata = sample_metadata(sample)
                    if metadata.get("technique"):
                        print(f"  Technique: {metadata['technique']}  fidelity={metadata.get('fidelity', '-')}")
                    print(f"  SHA256: {digest[:16]}...")
                    if package_digest != digest:
                        print(f"  Package: {package_digest[:16]}...  artifacts={len(sample_artifacts(sample, digest))}")
                    print("-" * 78, flush=True)
                    job_started = time.monotonic()
                    report = self._run_one(engine, sample, digest, package_digest)
                    report_name = f"{engine}_{package_digest}.json"
                    atomic_json_write(self.campaign_dir / "runs" / report_name, report)
                    self.state.save(engine, package_digest, {"status": report["status"], "report": f"runs/{report_name}", "updated_at": iso_now()})
                    self._print_result(report, time.monotonic() - job_started)
                    if report["status"] != "COMPLETED":
                        failures.append(f"{engine}:{sample.name}")
            finally:
                if started_services:
                    self.services.stop(engine)
        summary = self._write_summary(jobs, skipped, started_at)
        self._print_campaign_summary(summary, time.monotonic() - campaign_started)
        if failures:
            raise PipelineError(f"{len(failures)} job(s) failed: {', '.join(failures)}")

    def _run_one(self, engine: str, sample: Path, digest: str, package_digest: str | None = None) -> dict[str, Any]:
        package_digest = package_digest or sample_package_sha256(sample, digest)
        run_id = f"{self.campaign}-{engine}-{package_digest[:12]}"
        guest_dir = rf"C:\Detonation\runs\{run_id}"
        if sample.name != Path(sample.name).name or any(char in sample.name for char in '<>:"/\\|?*'):
            raise PipelineError(f"Sample name cannot be used as a Windows guest filename: {sample.name}")
        guest_file = guest_dir + "\\" + sample.name
        source_artifacts = sample_artifacts(sample, digest)
        artifacts = [{
            "role": item["role"],
            "name": item["name"],
            "sha256": item["sha256"],
            "host_path": str(item["path"]),
            "guest_path": guest_dir + "\\" + item["name"],
            "staged": False,
        } for item in source_artifacts]
        report: dict[str, Any] = {"run_id": run_id, "engine": engine, "snapshot": SNAPSHOTS[engine],
                                  "package_sha256": package_digest, "artifacts": artifacts,
                                  "sample": {"name": sample.name, "path": str(sample), "sha256": digest}, "status": "RUNNING"}

        def finish_static(blocked_artifact: dict[str, Any]) -> dict[str, Any]:
            self._phase("Static detection or quarantine occurred before execution")
            verdict = "DETECTED" if engine == "defender" else "NOT_EXECUTED"
            report.update({"status": "COMPLETED", "verdict": verdict, "stage": "STATIC",
                           "blocked_path": blocked_artifact["guest_path"],
                           "blocked_artifact": blocked_artifact["name"],
                           "execution_started_at": None, "execution_ended_at": iso_now()})
            if engine == "defender":
                report["defender"] = self._collect_defender(guest_dir, artifacts, report["copy_started_at"], report["execution_ended_at"])
            elif engine == "elastic":
                report["elastic"] = {"status": verdict, "reason": f"{blocked_artifact['name']} was blocked before execution"}
            else:
                report[engine] = self.collector.collect(engine, artifacts, report["copy_started_at"], report["execution_ended_at"])
            return report

        try:
            metadata = sample_metadata(sample)
            if metadata:
                report["sample"].update({key: metadata[key] for key in ("technique", "fidelity") if key in metadata})
            self._phase(f"Reverting VM to snapshot '{SNAPSHOTS[engine]}'")
            self.vmrun.revert(SNAPSHOTS[engine])
            self.vmrun.wait_for_tools()
            self._phase("VMware Tools ready")
            requires_image_load = engine == "wazuh" and any(
                item["role"] == "companion" and item["name"].lower().endswith(".dll") for item in artifacts
            )
            report["guest_health"] = self._wait_for_guest_health(engine, require_image_load=requires_image_load)
            self._phase("Guest health: " + self._guest_summary(report["guest_health"]))
            if engine == "elastic":
                self._phase("Waiting for Elastic Agent, Endpoint, and telemetry canary")
                report["elastic_readiness"] = self._wait_for_elastic_readiness(run_id, report["guest_health"])
            self.vmrun.create_directory(guest_dir)
            report["copy_started_at"] = iso_now()
            report["companions"] = [item for item in artifacts if item["role"] == "companion"]
            ordered_artifacts = [*zip(source_artifacts[1:], artifacts[1:]), (source_artifacts[0], artifacts[0])]
            for source_artifact, artifact in ordered_artifacts:
                label = "companion" if artifact["role"] == "companion" else "sample"
                self._phase(f"Copying {label}: {artifact['name']} and verifying SHA256")
                self.vmrun.copy_to_guest(source_artifact["path"].resolve(), artifact["guest_path"])
                actual_hash = ""
                hashes: list[str] = []
                exists = True
                for _ in range(10):
                    actual_hash = self.vmrun.run_powershell(
                        f"(Get-FileHash -Algorithm SHA256 -LiteralPath '{artifact['guest_path']}').Hash"
                    )
                    hashes = [line.strip() for line in actual_hash.splitlines() if len(line.strip()) == 64]
                    exists = self.vmrun.exists(artifact["guest_path"])
                    if hashes or not exists or any(marker in actual_hash.lower() for marker in (
                        "virus", "potentially unwanted", "operation did not complete successfully",
                    )):
                        break
                    time.sleep(1)
                blocked = not exists or any(marker in actual_hash.lower() for marker in (
                    "virus", "potentially unwanted", "operation did not complete successfully",
                ))
                if not hashes and blocked:
                    artifact["stage_status"] = "BLOCKED"
                    return finish_static(artifact)
                if not hashes or hashes[-1].lower() != artifact["sha256"].lower():
                    raise PipelineError(f"Guest SHA256 differs for {artifact['name']}: {actual_hash[-500:]!r}")
                artifact.update({"staged": True, "stage_status": "VERIFIED"})
            self._phase(f"Static observation: {self.settings.static_wait}s")
            time.sleep(self.settings.static_wait)
            for artifact in artifacts:
                artifact["present_after_static_wait"] = self.vmrun.exists(artifact["guest_path"])
                if not artifact["present_after_static_wait"]:
                    artifact["stage_status"] = "BLOCKED"
                    return finish_static(artifact)
            report["execution_started_at"] = iso_now()
            self._phase(f"Launching sample; detonation window: {self.settings.detonation_wait}s")
            self.vmrun.launch(guest_file, guest_dir)
            time.sleep(self.settings.detonation_wait)
            report["execution_ended_at"] = iso_now()
            if metadata.get("execution_profile") == "high_signal_v1":
                self._phase("Checking payload execution proof")
                report["execution_proof"] = self.vmrun.wait_for_execution_proof(guest_dir + r"\c1_pass.txt")
                self._phase("Payload execution proof observed")
            if engine != "defender":
                self._phase(f"Checking {engine} sample process telemetry")
                report["telemetry"] = self.collector.wait_for_sample_telemetry(engine, guest_file, digest, report["execution_started_at"])
                artifacts[0]["telemetry"] = "OBSERVED"
                artifacts[0]["telemetry_evidence"] = report["telemetry"]
                kind = "Child process" if report["telemetry"].get("evidence_type") == "child_process" else "Sample process"
                self._phase(f"{kind} telemetry observed")
                dll_companions = [item for item in report["companions"] if item["name"].lower().endswith(".dll")]
                if dll_companions:
                    self._phase(f"Checking {engine} companion DLL-load telemetry")
                    report["dll_telemetry"] = self.collector.wait_for_companion_telemetry(
                        engine, artifacts, report["execution_started_at"]
                    )
                    telemetry_by_name = {item["name"]: item for item in report["dll_telemetry"]}
                    for artifact in report["companions"]:
                        if artifact["name"] in telemetry_by_name:
                            artifact["telemetry"] = "LOADED"
                            artifact["telemetry_evidence"] = telemetry_by_name[artifact["name"]]
                    self._phase("Companion DLL-load telemetry observed")
                attempts = self.settings.elastic_poll_attempts if engine == "elastic" else self.settings.poll_attempts
                limit = "up to " if engine == "elastic" else ""
                self._phase(f"Collecting {engine} alerts: {limit}{attempts} polls x {self.settings.poll_wait}s")
            if engine == "defender":
                report["defender"] = self._collect_defender(guest_dir, artifacts, report["copy_started_at"], report["execution_ended_at"])
                report["verdict"] = report["defender"]["status"]
            else:
                report[engine] = self.collector.collect(engine, artifacts, report["execution_started_at"], report["execution_ended_at"])
                report["verdict"] = report[engine]["status"]
            report["status"] = "COMPLETED"
        except ExecutionFailure as error:
            report.update({"status": "EXECUTION_FAILURE", "stage": "RUNTIME", "error": str(error), "ended_at": iso_now()})
        except (PipelineError, requests.RequestException, OSError) as error:
            report.update({"status": "INFRA_FAILURE", "error": str(error), "ended_at": iso_now()})
        return report

    def _collect_defender(self, guest_dir: str, artifacts: list[dict[str, Any]], started: str, ended: str) -> dict[str, Any]:
        script = BASE_DIR / "pipeline" / "guest" / "collect_defender.ps1"
        guest_script = guest_dir + r"\collect_defender.ps1"
        guest_output = guest_dir + r"\defender.json"
        host_output = self.campaign_dir / "evidence" / f"defender_{guest_dir.rsplit(chr(92), 1)[-1]}.json"
        self.vmrun.copy_to_guest(script, guest_script)
        target_paths = ",".join("'" + item["guest_path"].replace("'", "''") + "'" for item in artifacts)
        command = f"& '{guest_script}' -StartUtc '{started}' -EndUtc '{ended}' -TargetPath @({target_paths}) -OutputPath '{guest_output}'"
        self.vmrun.run_powershell(command)
        self.vmrun.copy_from_guest(guest_output, host_output)
        data = json.loads(host_output.read_text(encoding="utf-8-sig"))
        data["evidence_path"] = str(host_output)
        if data.get("threat_query_error") and not data.get("defender_events"):
            raise PipelineError(f"Get-MpThreatDetection failed and no Defender event was found: {data['threat_query_error'][:200]}")
        data["status"] = "DETECTED" if data.get("defender_events") or data.get("threat_detections") else "NO_ALERT"
        evidence = {key: data.get(key) for key in ("defender_events", "threat_detections", "sysmon_events")}
        data["matched_artifacts"] = self.collector._matching_artifacts(evidence, artifacts)
        return data


def sample_paths(target: Path) -> list[Path]:
    if target.is_file():
        return [target] if target.suffix.lower() == ".exe" else []
    samples = sorted(path for path in target.rglob("*.exe") if path.is_file())
    return [sample for sample in samples if sample_metadata(sample).get("benchmark_ready", True)]


def main() -> int:
    parser = argparse.ArgumentParser(description="Direct vmrun dynamic EDR benchmark")
    parser.add_argument("command", choices=("doctor", "run"))
    parser.add_argument("target", nargs="?", help="EXE or directory, required for run")
    parser.add_argument("--campaign", default=datetime.now(timezone.utc).strftime("vmrun-%Y%m%dT%H%M%SZ"))
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--engines", default="elastic,wazuh,defender")
    parser.add_argument("--shuffle-seed", type=int)
    args = parser.parse_args()
    engines = [item.strip() for item in args.engines.split(",") if item.strip()]
    invalid = sorted(set(engines) - set(SNAPSHOTS))
    if invalid:
        parser.error("Unknown engine(s): " + ", ".join(invalid))
    try:
        runner = Runner(Settings.from_env(args.output_dir), args.campaign)
        with runner.lock():
            if args.command == "doctor":
                result = runner.doctor(engines)
                print(json.dumps(result, indent=2, ensure_ascii=False))
                return 0 if all(item.get("ready") for item in result["engines"].values()) else 2
            if not args.target:
                parser.error("target is required for run")
            samples = sample_paths(Path(args.target).resolve())
            if not samples:
                parser.error("No .exe samples found")
            runner.run(samples, engines, args.shuffle_seed)
            return 0
    except PipelineError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
