#!/usr/bin/env python3
"""Run focused C1 marker checks for advanced dataset samples in the isolated VM."""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from pipeline.vmrun_pipeline import PipelineError, Runner, Settings, json_from_output, sample_metadata


DEFAULT_SAMPLES = (
    "reflective_injection.exe",
    "mockingjay.exe",
    "module_stomp.exe",
)


def run_sample(runner: Runner, sample: Path, run_id: str) -> dict:
    metadata = sample_metadata(sample)
    companions = [sample.parent / name for name in metadata.get("companions", [])]
    missing = [path.name for path in companions if not path.is_file()]
    if missing:
        raise PipelineError(f"Missing companion artifact(s): {', '.join(missing)}")

    guest_dir = rf"C:\Detonation\runs\{run_id}"
    runner.vmrun.run_powershell(f"New-Item -ItemType Directory -Force -Path '{guest_dir}' | Out-Null")
    for artifact in [*companions, sample]:
        runner.vmrun.copy_to_guest(artifact.resolve(), guest_dir + "\\" + artifact.name)

    script = f"""
$ErrorActionPreference = 'Stop'
$dir = '{guest_dir}'
$exe = Join-Path $dir '{sample.name}'
$marker = Join-Path $dir 'c1_pass.txt'
Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
$process = Start-Process -FilePath $exe -WorkingDirectory $dir -Wait -PassThru
Start-Sleep -Milliseconds 500
$text = if (Test-Path -LiteralPath $marker) {{ Get-Content -LiteralPath $marker -Raw }} else {{ '' }}
[PSCustomObject]@{{
    exit_code = $process.ExitCode
    marker = ($text.Trim() -eq 'ALIVE')
    marker_text = $text.TrimEnd()
}} | ConvertTo-Json -Compress
"""
    result = json_from_output(runner.vmrun.run_powershell(script))
    result.update({
        "sample": sample.name,
        "companions": [path.name for path in companions],
        "passed": result.get("exit_code") == 0 and result.get("marker") is True,
    })
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", default=os.getenv("VMRUN_SNAPSHOT_WAZUH", "wazuh"))
    parser.add_argument("--samples", nargs="+", default=list(DEFAULT_SAMPLES))
    parser.add_argument("--keep-vm-running", action="store_true")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent
    build_dir = root / "build"
    samples = [build_dir / name for name in args.samples]
    missing = [path.name for path in samples if not path.is_file()]
    if missing:
        parser.error("Missing build artifact(s): " + ", ".join(missing))

    settings = Settings.from_env(Path("pipeline/vmrun_reports"))
    runner = Runner(settings, "c1-smoke")
    run_prefix = "c1-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    try:
        runner.vmrun.revert(args.snapshot)
        runner.vmrun.wait_for_tools()
        needs_image_load = any(sample_metadata(sample).get("companions") for sample in samples)
        health = runner._wait_for_guest_health("wazuh", require_image_load=needs_image_load)
        print(json.dumps({"health": health}, ensure_ascii=False))

        results = []
        for index, sample in enumerate(samples, 1):
            result = run_sample(runner, sample, f"{run_prefix}-{index:02d}")
            results.append(result)
            state = "PASS" if result["passed"] else "FAIL"
            print(f"C1 {state:<4} sample={sample.name} exit={result.get('exit_code')} marker={result.get('marker')}")
        print(json.dumps({"results": results}, ensure_ascii=False, indent=2))
        return 0 if all(result["passed"] for result in results) else 1
    finally:
        if not args.keep_vm_running:
            runner.vmrun.call("stop", "hard", check=False, timeout=30)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PipelineError as error:
        print(f"C1 INFRA_FAILURE: {error}", file=sys.stderr)
        raise SystemExit(2)
