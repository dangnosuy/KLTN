"""Minimal VMware Tools transport used only by the offline Defender scanner."""
from __future__ import annotations

import base64
import json
import os
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path


class VMwareError(RuntimeError):
    pass


def _positive_env(name: str, default: int) -> int:
    value = os.getenv(name, str(default))
    try:
        parsed = int(value)
    except ValueError as error:
        raise VMwareError(f"{name} must be a positive integer") from error
    if parsed <= 0:
        raise VMwareError(f"{name} must be a positive integer")
    return parsed


@dataclass(frozen=True)
class VMwareSettings:
    vmx: Path
    guest_user: str
    guest_password: str
    vm_password: str | None
    tools_timeout: int

    @classmethod
    def from_env(cls) -> "VMwareSettings":
        required = ("VMRUN_VMX", "VM_GUEST_USER", "VM_GUEST_PASSWORD")
        missing = [name for name in required if not os.getenv(name)]
        if missing:
            raise VMwareError("Missing required environment variables: " + ", ".join(missing))
        vmx = Path(os.environ["VMRUN_VMX"]).expanduser()
        if not vmx.is_file():
            raise VMwareError(f"VMX does not exist: {vmx}")
        return cls(
            vmx=vmx,
            guest_user=os.environ["VM_GUEST_USER"],
            guest_password=os.environ["VM_GUEST_PASSWORD"],
            vm_password=os.getenv("VMRUN_VM_PASSWORD"),
            tools_timeout=_positive_env("VMRUN_TOOLS_TIMEOUT_SECONDS", 120),
        )


class VMwareTransport:
    def __init__(self, settings: VMwareSettings):
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
            response = subprocess.run(
                self._command(command, *args, guest=guest),
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as error:
            raise VMwareError(f"vmrun {command} timed out after {timeout}s") from error
        if check and response.returncode:
            detail = (response.stderr or response.stdout).strip()
            raise VMwareError(f"vmrun {command} failed ({response.returncode}): {detail[:300]}")
        return response

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
            raise VMwareError(f"vmrun start nogui failed: {error}") from error

    def wait_for_tools(self) -> None:
        deadline = time.monotonic() + self.settings.tools_timeout
        last = ""
        while time.monotonic() < deadline:
            if self.start_process and (code := self.start_process.poll()) not in (None, 0):
                stdout, stderr = self.start_process.communicate()
                raise VMwareError(f"vmrun start nogui failed ({code}): {(stderr or stdout).strip()[:300]}")
            try:
                state = self.call("checkToolsState", check=False, timeout=15)
                tools = (state.stdout + state.stderr).strip()
                if tools.lower() in {"running", "installed"}:
                    probe = self.call(
                        "runProgramInGuest",
                        r"C:\Windows\System32\whoami.exe",
                        guest=True,
                        check=False,
                        timeout=min(60, max(1, int(deadline - time.monotonic()))),
                    )
                    if probe.returncode == 0:
                        return
                    last = f"Tools={tools}; guest probe={(probe.stderr or probe.stdout).strip()[:200]}"
                else:
                    last = tools
            except VMwareError as error:
                last = str(error)
            time.sleep(3)
        raise VMwareError(f"VMware guest operations did not become ready: {last[:300]}")

    def exists(self, path: str) -> bool:
        return self.call("fileExistsInGuest", path, guest=True, check=False).returncode == 0

    def copy_to_guest(self, source: Path, destination: str) -> None:
        self.call("CopyFileFromHostToGuest", str(source), destination, guest=True)

    def copy_from_guest(self, source: str, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        self.call("CopyFileFromGuestToHost", source, str(destination), guest=True)

    def create_directory(self, path: str) -> None:
        self.call("createDirectoryInGuest", path, guest=True)

    def run_powershell(self, script: str) -> str:
        token = f"{os.getpid()}-{uuid.uuid4().hex}"
        guest_output = rf"C:\Windows\Temp\detector-powershell-{token}.txt"
        host_output = Path("/tmp") / f"detector-powershell-{token}.txt"
        wrapper = (
            f"$p='{guest_output}'; try {{ $v=& {{ {script} }} *>&1 | Out-String -Width 4096; "
            "$v | Set-Content -LiteralPath $p -Encoding UTF8 } catch { "
            "$_ | Out-String | Set-Content -LiteralPath $p -Encoding UTF8; exit 1 }"
        )
        encoded = base64.b64encode(wrapper.encode("utf-16le")).decode("ascii")
        output = ""
        try:
            response = self.call(
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
            if response.returncode:
                detail = output or (response.stderr or response.stdout).strip()
                raise VMwareError(f"Guest PowerShell failed ({response.returncode}): {detail[:300]}")
            return output
        finally:
            self.call("deleteFileInGuest", guest_output, guest=True, check=False)
            host_output.unlink(missing_ok=True)


def json_document_from_output(text: str) -> dict:
    try:
        value = json.loads(text.lstrip("\ufeff").strip())
        if isinstance(value, dict):
            return value
    except json.JSONDecodeError:
        pass
    for line in reversed(text.splitlines()):
        try:
            value = json.loads(line)
            if isinstance(value, dict):
                return value
        except json.JSONDecodeError:
            pass
    raise VMwareError(f"Guest PowerShell did not return JSON: {text[-300:]}")
