from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pipeline.vmrun_pipeline import (
    PipelineError,
    Runner,
    Settings,
    SNAPSHOTS,
    VMRun,
    iso_now,
    json_document_from_output,
    sample_package_sha256,
    sample_paths,
    sha256_file,
)


class SingleRevertVMRun(VMRun):
    def __init__(self, settings: Settings):
        super().__init__(settings)
        self.active_snapshot: str | None = None
        self.reused_snapshot = False
        self.tools_ready = False
        self.last_launch: dict[str, Any] | None = None

    def can_reuse(self, snapshot: str) -> bool:
        return self.active_snapshot == snapshot and self.tools_ready

    def revert(self, snapshot: str) -> None:
        self.last_launch = None
        if self.can_reuse(snapshot):
            self.reused_snapshot = True
            return
        self.reused_snapshot = False
        self.tools_ready = False
        super().revert(snapshot)
        self.active_snapshot = snapshot

    def wait_for_tools(self) -> None:
        if self.reused_snapshot:
            return
        super().wait_for_tools()
        self.tools_ready = True

    def _process_ids(self) -> list[int]:
        output = self.run_powershell(
            "$pids=@(Get-CimInstance Win32_Process | ForEach-Object {[int]$_.ProcessId}); "
            "[PSCustomObject]@{pids=$pids}|ConvertTo-Json -Compress"
        )
        match = re.search(r'\{"pids":(?P<pids>\[[^]]*\]|\d+)\}', output)
        if not match:
            raise PipelineError(f"Guest process baseline did not return JSON: {output[-300:]}")
        value = match.group("pids")
        if value.startswith("["):
            return [int(item) for item in value[1:-1].split(",") if item.strip()]
        return [int(value)]

    def launch(self, path: str, working_directory: str) -> None:
        baseline_pids = self._process_ids()
        quoted_path = path.replace("'", "''")
        quoted_directory = working_directory.replace("'", "''")
        output = self.run_powershell(
            f"$p=Start-Process -FilePath '{quoted_path}' -WorkingDirectory '{quoted_directory}' -PassThru; $p.Id"
        )
        matches = re.findall(r"(?m)^\s*(\d+)\s*$", output)
        if not matches:
            raise PipelineError(f"Guest launcher did not return a PID: {output[-300:]}")
        self.last_launch = {
            "root_pid": int(matches[-1]),
            "baseline_pids": baseline_pids,
            "guest_dir": working_directory,
            "started_at": iso_now(),
        }

    def cleanup_run(self, guest_dir: str) -> dict[str, Any]:
        launch = self.last_launch if self.last_launch and self.last_launch["guest_dir"] == guest_dir else None
        baseline = ",".join(str(pid) for pid in (launch or {}).get("baseline_pids", []))
        root_pid = int((launch or {}).get("root_pid", 0))
        quoted_dir = guest_dir.replace("'", "''")
        # shortcut: process lineage and run files are cleaned; unknown persistence requires a stricter sandbox.
        script = f"""
$baseline=@({baseline}); $rootPid={root_pid}; $runPath='{quoted_dir}'
$all=@(Get-CimInstance Win32_Process)
$owned=[System.Collections.Generic.HashSet[int]]::new()
if($rootPid -gt 0){{[void]$owned.Add($rootPid)}}
do {{
  $changed=$false
  foreach($p in $all){{
    $pidValue=[int]$p.ProcessId; $parentValue=[int]$p.ParentProcessId
    if(($baseline -notcontains $pidValue) -and $owned.Contains($parentValue) -and $owned.Add($pidValue)){{$changed=$true}}
  }}
}} while($changed)
$targets=@($all | Where-Object {{
  $pidValue=[int]$_.ProcessId
  (($baseline -notcontains $pidValue) -and $owned.Contains($pidValue)) -or
  ($_.ExecutablePath -and $_.ExecutablePath.StartsWith($runPath,[System.StringComparison]::OrdinalIgnoreCase))
}})
$targetIds=@($targets | ForEach-Object {{[int]$_.ProcessId}})
foreach($pidValue in $targetIds){{Stop-Process -Id $pidValue -Force -ErrorAction SilentlyContinue}}
Start-Sleep -Seconds 1
$remaining=@(Get-CimInstance Win32_Process | Where-Object {{
  ($targetIds -contains [int]$_.ProcessId) -or
  ($_.ExecutablePath -and $_.ExecutablePath.StartsWith($runPath,[System.StringComparison]::OrdinalIgnoreCase))
}} | ForEach-Object {{[int]$_.ProcessId}})
Remove-Item -LiteralPath $runPath -Recurse -Force -ErrorAction SilentlyContinue
[PSCustomObject]@{{root_pid=$rootPid;killed_pids=$targetIds;remaining_pids=$remaining;directory_removed=(-not (Test-Path -LiteralPath $runPath))}} | ConvertTo-Json -Compress
"""
        output = self.run_powershell(script)
        match = re.search(r"\{.*\}", output, re.DOTALL)
        if not match:
            raise PipelineError(f"Guest cleanup did not return JSON: {output[-300:]}")
        result = json.loads(match.group(0))
        result["status"] = "PASSED" if result.get("directory_removed") and not result.get("remaining_pids") else "FAILED"
        self.last_launch = None
        return result


class SingleRevertRunner(Runner):
    def __init__(self, settings: Settings, campaign: str):
        super().__init__(settings, campaign)
        self.vmrun = SingleRevertVMRun(settings)
        self.elastic_readiness: dict[str, Any] | None = None
        self.elastic_agent_refreshed = False
        self.elastic_cold_booted = False
        self.contaminated_engines: dict[str, str] = {}

    def _phase(self, message: str) -> None:
        if message.startswith("Reverting VM to snapshot '"):
            snapshot = message.split("'", 2)[1]
            if self.vmrun.can_reuse(snapshot):
                message = f"Reusing warm VM session on snapshot '{snapshot}'"
        elif message == "VMware Tools ready" and self.vmrun.reused_snapshot:
            message = "Warm VM session ready"
        elif message.startswith("Waiting for Elastic Agent") and self.elastic_readiness:
            message = "Reusing validated Elastic readiness and telemetry canary"
        super()._phase(message)

    def _wait_for_elastic_readiness(self, run_id: str, guest: dict[str, Any]) -> dict[str, Any]:
        if self.elastic_readiness is None:
            if not self.elastic_cold_booted:
                # A memory snapshot can preserve Endpoint's 15-minute output backoff.
                self._phase("Cold-booting Elastic VM to clear Endpoint output backoff")
                self.vmrun.call("reset", "hard", timeout=30)
                self.vmrun.tools_ready = False
                self.vmrun.reused_snapshot = False
                self.vmrun.wait_for_tools()
                guest = self._wait_for_guest_health("elastic")
                self.elastic_cold_booted = True
            if not self.elastic_agent_refreshed:
                self._phase("Refreshing Elastic Agent after snapshot revert")
                self.vmrun.run_powershell('Restart-Service -Name "Elastic Agent" -Force; Start-Sleep -Seconds 5')
                self.elastic_agent_refreshed = True
            self.elastic_readiness = super()._wait_for_elastic_readiness(run_id, guest)
        return self.elastic_readiness

    def _elastic_endpoint_status(self) -> dict[str, Any]:
        status = super()._elastic_endpoint_status()
        runtime = json_document_from_output(self.vmrun.run_powershell(
            """$status=& "C:\\Program Files\\Elastic\\Agent\\elastic-agent.exe" status --output json | ConvertFrom-Json
$endpoint=@($status.components | Where-Object {$_.id -eq "endpoint"})[0]
[PSCustomObject]@{component_state=$endpoint.state;units=@($endpoint.units | ForEach-Object {[PSCustomObject]@{state=$_.state;message=$_.message;output_error=[string]$_.payload.error.message}})} | ConvertTo-Json -Compress -Depth 5"""
        ))
        items = status.get("endpoint") or []
        component = next((item for item in items if item.get("id") == "endpoint"), None)
        units = [item for item in items if item.get("id") != "endpoint"]
        applied_policy = all(
            item.get("state") == 2 or "Applied policy" in str(item.get("message", ""))
            for item in units
        )
        output_errors = [
            unit.get("output_error") for unit in runtime.get("units") or []
            if unit.get("output_error") and unit.get("output_error") != "Success"
        ]
        status["endpoint_output_errors"] = output_errors
        status["healthy"] = bool(
            component and component.get("state") == 2 and runtime.get("component_state") == 2
            and applied_policy and not output_errors and status.get("agent_policy_revision")
        )
        if status["healthy"] and status.get("agent_state") != 2:
            status["agent_warning"] = status.get("agent_message")
        return status

    def _guest_health(self, engine: str, require_image_load: bool = False) -> dict[str, Any]:
        health = super()._guest_health(engine, require_image_load=require_image_load)
        if engine != "wazuh":
            return health
        check_connection = (
            "[xml]$config=Get-Content -LiteralPath 'C:\\Program Files (x86)\\ossec-agent\\ossec.conf' -Raw; "
            "$server=[string]$config.ossec_config.client.server.address; "
            "[PSCustomObject]@{server=$server;tcp1514=[bool](Test-NetConnection -ComputerName $server -Port 1514 -InformationLevel Quiet)} "
            "| ConvertTo-Json -Compress"
        )
        connection = json_document_from_output(self.vmrun.run_powershell(check_connection))
        if connection.get("server") and not connection.get("tcp1514"):
            self._phase("Wazuh Manager unreachable; renewing guest DHCP lease")
            self.vmrun.run_powershell("ipconfig /renew")
            connection = json_document_from_output(self.vmrun.run_powershell(check_connection))
        if not connection.get("server") or not connection.get("tcp1514"):
            raise PipelineError(f"Wazuh Manager TCP/1514 is unreachable at {connection.get('server') or 'unknown'}")
        health["wazuh_manager"] = connection
        return health

    def _not_run_report(self, engine: str, sample: Path, digest: str, package_digest: str) -> dict[str, Any]:
        reason = self.contaminated_engines[engine]
        return {
            "run_id": f"{self.campaign}-{engine}-{package_digest[:12]}",
            "engine": engine,
            "snapshot": SNAPSHOTS[engine],
            "package_sha256": package_digest,
            "sample": {"name": sample.name, "path": str(sample), "sha256": digest},
            "status": "NOT_RUN_CONTAMINATED",
            "verdict": "N/A",
            "error": f"Warm VM session stopped after cleanup failure: {reason}",
        }

    def _run_one(self, engine: str, sample: Path, digest: str, package_digest: str | None = None) -> dict[str, Any]:
        package_digest = package_digest or sample_package_sha256(sample, digest)
        if engine in self.contaminated_engines:
            return self._not_run_report(engine, sample, digest, package_digest)
        if engine == "elastic" and not self.vmrun.can_reuse(SNAPSHOTS[engine]):
            self.elastic_readiness = None
            self.elastic_agent_refreshed = False
            self.elastic_cold_booted = False

        guest_dir = rf"C:\Detonation\runs\{self.campaign}-{engine}-{package_digest[:12]}"
        report = super()._run_one(engine, sample, digest, package_digest)
        report["session"] = {
            "mode": "single_revert",
            "snapshot_reused": self.vmrun.reused_snapshot,
        }

        if not self.vmrun.tools_ready:
            reason = "VMware Tools did not become ready; cleanup could not be verified"
            report["cleanup"] = {"status": "SKIPPED", "reason": reason}
            self.contaminated_engines[engine] = reason
            return report

        try:
            self._phase("Cleaning run processes and guest artifacts")
            cleanup = self.vmrun.cleanup_run(guest_dir)
            report["cleanup"] = cleanup
            if cleanup["status"] != "PASSED":
                raise PipelineError(
                    f"remaining processes={cleanup.get('remaining_pids', [])}, "
                    f"directory_removed={cleanup.get('directory_removed')}"
                )
            health = self._guest_health(engine)
            report["post_cleanup_health"] = health
            if engine == "elastic" and not self._elastic_endpoint_status().get("healthy"):
                raise PipelineError("Elastic Endpoint is not healthy after cleanup")
            report["session_validation"] = {"status": "PASSED"}
            self._phase("Cleanup verified; warm VM can run the next sample")
        except PipelineError as error:
            reason = str(error)
            if (report.get("cleanup") or {}).get("status") == "PASSED":
                report["session_validation"] = {"status": "FAILED", "reason": reason}
            else:
                report["cleanup"] = {**report.get("cleanup", {}), "status": "FAILED", "reason": reason}
            report["pre_cleanup_status"] = report.get("status")
            report["pre_cleanup_verdict"] = report.get("verdict", "N/A")
            report.update({"status": "CONTAMINATED", "verdict": "N/A", "error": f"Cleanup gate failed: {reason}"})
            self.contaminated_engines[engine] = reason
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Single-revert warm VM EDR benchmark")
    parser.add_argument("command", choices=("doctor", "run"))
    parser.add_argument("target", nargs="?", help="EXE or directory, required for run")
    parser.add_argument("--campaign", default=datetime.now(timezone.utc).strftime("single-revert-%Y%m%dT%H%M%SZ"))
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--engines", default="elastic,wazuh,defender")
    parser.add_argument("--shuffle-seed", type=int)
    args = parser.parse_args()
    engines = [item.strip() for item in args.engines.split(",") if item.strip()]
    invalid = sorted(set(engines) - set(SNAPSHOTS))
    if invalid:
        parser.error("Unknown engine(s): " + ", ".join(invalid))
    try:
        settings = Settings.from_env(args.output_dir)
        runner = SingleRevertRunner(settings, args.campaign)
        with runner.lock():
            if args.command == "doctor":
                result = runner.doctor(engines)
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
