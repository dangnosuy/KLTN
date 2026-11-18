from __future__ import annotations

import base64
import re
import subprocess
import time
import uuid
from pathlib import Path

from .core import failed, log, result
from .vmware import VMwareSettings, VMwareTransport, json_document_from_output


def ps_quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def parse_scan(code, stdout, stderr=""):
    text = stdout + "\n" + stderr
    threats = re.findall(r"(?im)^\s*Threat(?:\s+Name)?\s*:\s*(.+?)\s*$", text)
    scan_error = re.search(r"(?im)(scan failed|scanning failed|error\s*[:=]|0x[89a-f][0-9a-f]{7})", text)
    if code not in (0, 2) or scan_error:
        return failed(f"Defender scan failed ({code}); inspect raw CLI output", "INFRA_FAILURE")
    if threats:
        return result(True, threat_names=threats, returncode=code)
    if code == 0 and re.search(r"(?i)found no threats", text):
        return result(False, threat_names=[], returncode=code)
    return failed(f"Ambiguous Defender output ({code}); not treated as a clean scan", "INFRA_FAILURE")


def validate_health(health, staging_dir):
    if not health.get("service_enabled") or not health.get("antivirus_enabled") or not health.get("scanner"):
        raise RuntimeError("Defender scanner/service is unavailable")
    if health.get("maps_reporting") != 0 or health.get("sample_consent") != 2 or health.get("block_at_first_seen_disabled") is not True:
        raise RuntimeError("Defender must be offline: MAPSReporting=0, SubmitSamplesConsent=2, DisableBlockAtFirstSeen=true")
    exclusions = health.get("exclusions") or []
    if isinstance(exclusions, str):
        exclusions = [exclusions]
    if staging_dir.rstrip("\\").casefold() not in {str(path).rstrip("\\").casefold() for path in exclusions}:
        raise RuntimeError("Dedicated Defender staging directory must be excluded from on-access scanning before transport")
    if not health.get("signature_version") or not health.get("engine_version"):
        raise RuntimeError("Missing Defender engine/signature version")
    return {key: health[key] for key in ("engine_version", "signature_version", "platform_version", "scanner")}


class DefenderScanner:
    def __init__(self, config):
        self.config = config["defender"]
        self.vm = None
        self.ready = False
        self.poisoned = False

    def transport(self):
        if self.vm is None:
            self.vm = VMwareTransport(VMwareSettings.from_env())
        return self.vm

    def health(self):
        vm = self.transport()
        output = vm.run_powershell(r"""
$ErrorActionPreference='Stop'
$s=Get-MpComputerStatus; $p=Get-MpPreference
$exe=Get-ChildItem 'C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe' -ErrorAction SilentlyContinue |
  Sort-Object {[version]$_.Directory.Name.Split('-')[0]} -Descending | Select-Object -First 1 -ExpandProperty FullName
if(-not $exe){$exe='C:\Program Files\Windows Defender\MpCmdRun.exe'}
if(-not (Test-Path -LiteralPath $exe)){$exe=$null}
[PSCustomObject]@{service_enabled=$s.AMServiceEnabled;antivirus_enabled=$s.AntivirusEnabled;
 scanner=$exe;maps_reporting=[int]$p.MAPSReporting;sample_consent=[int]$p.SubmitSamplesConsent;
 block_at_first_seen_disabled=[bool]$p.DisableBlockAtFirstSeen;exclusions=@($p.ExclusionPath);
 engine_version=$s.AMEngineVersion;signature_version=$s.AntivirusSignatureVersion;platform_version=$s.AMProductVersion} |
 ConvertTo-Json -Compress
""")
        health = json_document_from_output(output)
        version = validate_health(health, self.config["staging_dir"])
        return health, version

    def doctor(self):
        _, version = self.health()
        return {"version": version, "offline": True, "snapshot": self.config["snapshot"], "note": "Current guest inspected; snapshot is validated again after revert during run"}

    def scan(self, artifact):
        if self.poisoned:
            return failed("Defender VM session is unsafe after an earlier scan/cleanup failure; start a new invocation", "INFRA_FAILURE")
        vm = self.transport()
        if not self.ready:
            log(f"DEFENDER reverting to {self.config['snapshot']} (static scan only)")
            vm.revert(self.config["snapshot"])
            self.ready = True
            vm.wait_for_tools()
        health, version = self.health()
        root = self.config["staging_dir"] + "\\" + uuid.uuid4().hex
        source = root + "\\input\\" + artifact["name"]
        scan_result = root + "\\scan-result.json"
        pid = None
        response = None
        try:
            vm.create_directory(root)
            vm.create_directory(root + "\\input")
            vm.copy_to_guest(Path(artifact["path"]), source)
            copied = json_document_from_output(vm.run_powershell(
                f"$ErrorActionPreference='Stop'; @{{sha256=(Get-FileHash -LiteralPath {ps_quote(source)} -Algorithm SHA256).Hash}} | ConvertTo-Json -Compress"
            ))
            if copied.get("sha256", "").lower() != artifact["sha256"]:
                raise RuntimeError("Defender staging hash mismatch or file quarantined before CLI scan")
            script = (
                "$ErrorActionPreference='Stop'; $result=try { "
                f"$output=& {ps_quote(health['scanner'])} -Scan -ScanType 3 -File {ps_quote(source)} -DisableRemediation 2>&1; "
                "$code=$LASTEXITCODE; $text=$output | Out-String -Width 4096; "
                "@{returncode=$code;stdout=$text;stderr=''} | ConvertTo-Json -Compress "
                "} catch { @{returncode=-1;stdout='';stderr=($_|Out-String)} | ConvertTo-Json -Compress }; "
                f"$result | Set-Content -LiteralPath {ps_quote(scan_result + '.tmp')} -Encoding UTF8; "
                f"Move-Item -LiteralPath {ps_quote(scan_result + '.tmp')} -Destination {ps_quote(scan_result)}"
            )
            # Only this trusted helper and MpCmdRun are started; source is always a -File argument.
            encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
            launch = json_document_from_output(vm.run_powershell(
                "$p=Start-Process -FilePath 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' "
                f"-ArgumentList '-NoProfile -NonInteractive -EncodedCommand {encoded}' -PassThru -WindowStyle Hidden; "
                "@{pid=$p.Id}|ConvertTo-Json -Compress"
            ))
            pid = int(launch["pid"])
            deadline = time.monotonic() + self.config["timeout"]
            while time.monotonic() < deadline:
                state = json_document_from_output(vm.run_powershell(
                    f"if(Test-Path -LiteralPath {ps_quote(scan_result)}){{Get-Content -LiteralPath {ps_quote(scan_result)} -Raw}}"
                    "else{'{\"pending\":true}'}"
                ))
                if not state.get("pending"):
                    response = parse_scan(state["returncode"], state["stdout"], state.get("stderr", ""))
                    response.update(stdout=state["stdout"], stderr=state.get("stderr", ""), version=version, offline=True, stage="STATIC")
                    break
                log(f"DEFENDER scanning {artifact['name']}; waiting for CLI completion")
                time.sleep(2)
            if response is None:
                raise TimeoutError(f"Defender CLI exceeded {self.config['timeout']}s")
            _, after = self.health()
            if after != version:
                raise RuntimeError("Defender version changed during scan")
            return response
        except Exception:
            self.poisoned = True
            raise
        finally:
            try:
                if response is None and pid:
                    vm.run_powershell(f"& taskkill.exe /PID {pid} /T /F | Out-Null")
                output = vm.run_powershell(
                    f"$ErrorActionPreference='Stop'; Remove-Item -LiteralPath {ps_quote(root)} -Recurse -Force -ErrorAction SilentlyContinue; "
                    f"if(Test-Path -LiteralPath {ps_quote(root)}){{throw 'Defender staging cleanup failed'}}; 'removed'"
                )
                if output.strip() != "removed":
                    raise RuntimeError("Defender staging cleanup could not be verified")
            except Exception as error:
                self.poisoned = True
                raise RuntimeError("Defender staging cleanup failed; VM session stopped") from error

    def close(self):
        if self.vm and self.ready:
            log("DEFENDER stopping scan VM before CAPE/exit")
            self.vm.call("stop", "hard", timeout=30)
            self.ready = False
        if self.vm and self.vm.start_process:
            process = self.vm.start_process
            try:
                process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.communicate(timeout=10)
