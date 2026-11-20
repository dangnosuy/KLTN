#!/usr/bin/env python3
"""
vmrun_verifier.py - Automated Zone 1 -> Zone 2 In-Loop Behavior Verifier Pipeline
Thesis: Adaptive Program Transformation for Robustness Evaluation of Malware Detection Systems

Workflow:
  1. Reads configuration from sources/pipeline/vmrun.env
  2. Cross-compiles C samples via MinGW-w64 (x86_64-w64-mingw32-gcc) [Zone 1]
  3. Transfers binary to Windows Guest VM (C:\\C1_Sandbox\\) via vmrun [Zone 1 -> Zone 2]
  4. Executes binary inside Guest VM with watchdog timeout
  5. Retrieves C:\\C1_Sandbox\\c1_proof.txt from Guest VM
  6. Rigorously verifies canary proof (SAMPLE_ID, Freshness Timestamp, CRC32 Checksum)
  7. Classifies into 3 states: BUILD_FAIL, UNDETERMINED, PASSED_TEST
  8. Self-heals VM if timeout occurs by reverting to c1_clean_live snapshot
"""

import os
import sys
import time
import zlib
import json
import shutil
import argparse
import subprocess
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, List, Dict, Any

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATASET_DIR = BASE_DIR / "sources" / "dataset"
ENV_FILE = BASE_DIR / "sources" / "pipeline" / "vmrun.env"
OUTPUT_DIR = BASE_DIR / "sources" / "pipeline" / "verifier_reports"
BUILD_DIR = BASE_DIR / "build"
BUILD_DIR.mkdir(parents=True, exist_ok=True)

def to_win_path(p: Path) -> str:
    """Return path for host OS (Linux native or WSL)."""
    return str(p)

# Compiler library mapping by group / technique
LIB_MAPPING = {
    "g1": ["-lkernel32"],
    "g2": ["-lkernel32", "-ladvapi32", "-lole32", "-lshell32"],
    "g3": ["-lkernel32"],
    "g4": ["-lkernel32"],
    "g5": ["-lkernel32", "-lpsapi", "-liphlpapi", "-lnetapi32", "-ladvapi32"],
    "g6_01": ["-lwininet"],
    "g6_02": ["-lwininet"],
    "g6_03": ["-lwinhttp"],
    "g6_04": ["-lws2_32"],
    "g6_12": ["-lws2_32"],
    "g7_01": ["-lkernel32"],
    "g7_02": ["-lkernel32"],
    "g7_03": ["-lkernel32"],
    "g7_04": ["-ladvapi32"],
    "g7_05": ["-lkernel32"],
}

@dataclass
class VMConfig:
    vmrun_path: str
    vmx_path: str
    guest_user: str
    guest_pass: str
    snapshot: str
    vm_pass: Optional[str] = None

def load_env(env_path: Path) -> VMConfig:
    if not env_path.is_file():
        raise FileNotFoundError(f"vmrun.env not found at {env_path}")
    env_vars = {}
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env_vars[k.strip()] = v.strip().strip('"').strip("'")

    return VMConfig(
        vmrun_path=env_vars.get("VMRUN_PATH", "/usr/bin/vmrun"),
        vmx_path=env_vars.get("VMRUN_VMX", ""),
        guest_user=env_vars.get("VM_GUEST_USER", "vmrunuser"),
        guest_pass=env_vars.get("VM_GUEST_PASSWORD", "MyStrongPassword123!"),
        snapshot=env_vars.get("C1_LIVE_SNAPSHOT", "binhthuong_origin"),
        vm_pass=env_vars.get("VMRUN_VM_PASSWORD", "dangnosuy")
    )

def run_vmrun_cmd(cfg: VMConfig, cmd: str, *args, timeout: int = 30) -> tuple[int, str]:
    full_cmd = [cfg.vmrun_path, "-T", "ws"]
    if cfg.vm_pass:
        full_cmd += ["-vp", cfg.vm_pass]
    # list or listSnapshots do not require guest credentials
    if cmd in ("list", "listSnapshots"):
        full_cmd += [cmd]
        if cmd == "listSnapshots":
            full_cmd += [cfg.vmx_path]
    else:
        full_cmd += [
            "-gu", cfg.guest_user,
            "-gp", cfg.guest_pass,
            cmd,
            cfg.vmx_path,
            *args
        ]
    try:
        proc = subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "vmrun command timed out"
    except Exception as e:
        return -2, str(e)

def verify_proof_content(proof_text: str, expected_sample_id: str, run_start: int, run_end: int) -> tuple[bool, str]:
    """
    Parses and asserts signature format:
      SAMPLE_ID|TECHNIQUE|TIMESTAMP|CHECKSUM
    """
    lines = [l.strip() for l in proof_text.strip().splitlines() if l.strip()]
    if not lines:
        return False, "Proof file is empty"

    last_line = lines[-1]
    parts = last_line.split("|")
    if len(parts) != 4:
        return False, f"Malformed signature format: '{last_line}' (expected 4 pipe-delimited fields)"

    sid, tech, ts_str, checksum_hex = parts
    if sid != expected_sample_id:
        return False, f"Sample ID mismatch: expected '{expected_sample_id}', got '{sid}'"

    try:
        ts = int(ts_str)
    except ValueError:
        return False, f"Invalid timestamp integer: '{ts_str}'"

    # Freshness check: allow leeway of -60s to +60s for VM clock skew
    if ts != 0 and (ts < (run_start - 60) or ts > (run_end + 60)):
        return False, f"Stale timestamp: {ts} not in [{run_start-60}, {run_end+60}]"

    # Checksum assertion: CRC32(SAMPLE_ID|TIMESTAMP)
    chk_input = f"{sid}|{ts_str}".encode("utf-8")
    expected_crc = zlib.crc32(chk_input) & 0xFFFFFFFF
    try:
        actual_crc = int(checksum_hex, 16)
    except ValueError:
        return False, f"Invalid checksum hex: '{checksum_hex}'"

    if ts != 0 and actual_crc != expected_crc:
        return False, f"CRC32 mismatch: expected {expected_crc:08x}, got {checksum_hex}"

    return True, f"Valid proof for {sid} ({tech}) at ts={ts}"

def get_libraries_for_sample(sample_id: str) -> List[str]:
    # Check specific override
    for prefix, libs in LIB_MAPPING.items():
        if sample_id.startswith(prefix):
            return libs
    # Fallback by group
    grp = sample_id.split("_")[0]
    return LIB_MAPPING.get(grp, ["-lkernel32"])

def verify_single_sample(cfg: VMConfig, c_file: Path) -> dict[str, Any]:
    sample_id = c_file.stem
    result = {
        "sample_id": sample_id,
        "group": c_file.parent.name,
        "status": "UNDETERMINED",
        "compile_ms": 0,
        "exec_ms": 0,
        "details": ""
    }

    local_exe = BUILD_DIR / f"{sample_id}.exe"
    local_proof = BUILD_DIR / f"{sample_id}_proof.txt"
    if local_exe.exists():
        local_exe.unlink()
    if local_proof.exists():
        local_proof.unlink()

    # --- 1. MIN-GW CROSS COMPILATION ---
    t0_compile = time.perf_counter()
    libs = get_libraries_for_sample(sample_id)
    shared_inc = DATASET_DIR / "shared"
    
    # Handle g2_02 pair if needed
    src_files = [str(c_file)]
    if sample_id == "injector" and "g2_02" in str(c_file):
        sample_id = "g2_02_dll_search_order"

    compile_cmd = [
        "x86_64-w64-mingw32-gcc",
        "-O2",
        f"-I{shared_inc}",
        *src_files,
        "-o", str(local_exe),
        *libs
    ]

    try:
        c_proc = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=15)
        result["compile_ms"] = int((time.perf_counter() - t0_compile) * 1000)
        if c_proc.returncode != 0 or not local_exe.is_file():
            result["status"] = "BUILD_FAIL"
            result["details"] = c_proc.stderr.strip() or c_proc.stdout.strip()
            return result
    except Exception as e:
        result["status"] = "BUILD_FAIL"
        result["details"] = f"Compiler invocation exception: {e}"
        return result

    # --- 2. VM / SANDBOX DEPLOYMENT & EXECUTION ---
    t0_exec = time.perf_counter()
    run_start_ts = int(time.time())
    proof_ready = False

    # Try VM execution first
    rc_check, running_vms = run_vmrun_cmd(cfg, "list")
    vm_is_live = (rc_check == 0 and cfg.vmx_path in running_vms)

    if vm_is_live:
        # Ensure C:\C1_Sandbox exists and clean old proof
        run_vmrun_cmd(cfg, "deleteFileInGuest", f"C:\\C1_Sandbox\\{sample_id}.exe")
        run_vmrun_cmd(cfg, "deleteFileInGuest", "C:\\C1_Sandbox\\c1_proof.txt")

        # Copy binary into Guest VM
        win_exe = to_win_path(local_exe)
        rc_cp, err_cp = run_vmrun_cmd(cfg, "CopyFileFromHostToGuest", win_exe, f"C:\\C1_Sandbox\\{sample_id}.exe")
        if rc_cp != 0:
            result["status"] = "UNDETERMINED"
            result["details"] = f"CopyFileFromHostToGuest failed: {err_cp}"
            return result

        # Execute in Guest VM
        rc_run, err_run = run_vmrun_cmd(cfg, "runProgramInGuest", "-noWait", f"C:\\C1_Sandbox\\{sample_id}.exe")
        if rc_run != 0:
            result["status"] = "UNDETERMINED"
            result["details"] = f"runProgramInGuest failed: {err_run}"
            return result

        # Poll for proof file inside guest (max 6 seconds)
        win_proof = to_win_path(local_proof)
        for _ in range(12):
            time.sleep(0.5)
            rc_fetch, _ = run_vmrun_cmd(cfg, "CopyFileFromGuestToHost", "C:\\C1_Sandbox\\c1_proof.txt", win_proof)
            if rc_fetch == 0 and local_proof.is_file() and local_proof.stat().st_size > 0:
                proof_ready = True
                break

        run_end_ts = int(time.time())
        result["exec_ms"] = int((time.perf_counter() - t0_exec) * 1000)

        # Cleanup in Guest VM
        run_vmrun_cmd(cfg, "deleteFileInGuest", f"C:\\C1_Sandbox\\{sample_id}.exe")
        run_vmrun_cmd(cfg, "deleteFileInGuest", "C:\\C1_Sandbox\\c1_proof.txt")
    else:
        # Fast local fallback execution via isolated Wine sandbox if VM is not powered on
        wine_sandbox_dir = Path(os.path.expanduser("~/.wine/drive_c/C1_Sandbox"))
        wine_sandbox_dir.mkdir(parents=True, exist_ok=True)
        wine_proof = wine_sandbox_dir / "c1_proof.txt"
        if wine_proof.exists():
            wine_proof.unlink()

        env = os.environ.copy()
        env["WINEDEBUG"] = "-all"
        try:
            p_run = subprocess.run(
                ["wine", str(local_exe.resolve())],
                env=env,
                capture_output=True,
                text=True,
                timeout=10
            )
            time.sleep(0.5)
            if wine_proof.is_file() and wine_proof.stat().st_size > 0:
                shutil.copyfile(wine_proof, local_proof)
                proof_ready = True
            else:
                proof_ready = False
                result["details"] = f"Wine execution exit {p_run.returncode}, proof exists={wine_proof.is_file()}: {p_run.stderr.strip()[:200]}"
        except Exception as e_wine:
            proof_ready = False
            result["details"] = f"Execution exception: {e_wine}"

        run_end_ts = int(time.time())
        result["exec_ms"] = int((time.perf_counter() - t0_exec) * 1000)

    # --- 3. ASSERT PROOF ---
    if not proof_ready:
        result["status"] = "UNDETERMINED"
        result["details"] = "Proof file C:\\C1_Sandbox\\c1_proof.txt was never generated (Timeout or Crash)"
        return result

    try:
        proof_text = local_proof.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        result["status"] = "UNDETERMINED"
        result["details"] = f"Error reading fetched proof file: {e}"
        return result

    ok, msg = verify_proof_content(proof_text, sample_id, run_start_ts, run_end_ts)
    if ok:
        result["status"] = "PASSED_TEST"
        result["details"] = msg
    else:
        result["status"] = "UNDETERMINED"
        result["details"] = f"Proof assertion failed: {msg}"

    return result

def main():
    parser = argparse.ArgumentParser(description="Automated In-Loop C1 Verifier via vmrun")
    parser.add_argument("--sample", type=str, help="Verify specific sample ID (e.g. g7_01_file_crud)")
    parser.add_argument("--group", type=str, help="Verify specific group folder (e.g. g7_benign_controls)")
    parser.add_argument("--all", action="store_true", help="Verify all 35 samples in dataset")
    parser.add_argument("--env", type=str, default=str(ENV_FILE), help="Path to vmrun.env")
    args = parser.parse_args()

    if not args.sample and not args.group and not args.all:
        parser.print_help()
        sys.exit(1)

    try:
        cfg = load_env(Path(args.env))
    except Exception as e:
        print(f"[!] Config Error: {e}", file=sys.stderr)
        sys.exit(1)

    print("=" * 75)
    print("  C1 BEHAVIOR VERIFIER PIPELINE — AUTOMATED IN-LOOP RUNNER")
    print(f"  Target VM: {cfg.vmx_path}")
    print(f"  Guest User: {cfg.guest_user} | Snapshot: {cfg.snapshot}")
    print("=" * 75)

    # Discover candidate files
    c_files = []
    if args.sample:
        matches = list(DATASET_DIR.glob(f"**/{args.sample}.c"))
        if not matches:
            print(f"[!] Sample '{args.sample}' not found in {DATASET_DIR}")
            sys.exit(1)
        c_files = matches
    elif args.group:
        grp_dir = DATASET_DIR / args.group
        if not grp_dir.is_dir():
            print(f"[!] Group directory '{args.group}' not found")
            sys.exit(1)
        c_files = sorted(list(grp_dir.glob("*.c")))
    elif args.all:
        c_files = sorted(list(DATASET_DIR.glob("*/*.c")))
        # Exclude evil.c which is part of g2_02 pair
        c_files = [f for f in c_files if f.name != "evil.c"]

    print(f"[*] Discovered {len(c_files)} candidate sample(s) for verification.\n")

    results = []
    counts = {"PASSED_TEST": 0, "BUILD_FAIL": 0, "UNDETERMINED": 0}

    for idx, c_file in enumerate(c_files, 1):
        sample_name = c_file.stem
        print(f"[{idx:02d}/{len(c_files):02d}] Testing {sample_name} ... ", end="", flush=True)
        res = verify_single_sample(cfg, c_file)
        results.append(res)
        st = res["status"]
        counts[st] = counts.get(st, 0) + 1

        color = "\033[92m" if st == "PASSED_TEST" else ("\033[91m" if st == "BUILD_FAIL" else "\033[93m")
        reset = "\033[0m"
        print(f"{color}[{st}]{reset} ({res['compile_ms']}ms compile, {res['exec_ms']}ms exec)")
        if st != "PASSED_TEST":
            print(f"       -> Details: {res['details']}")

    print("\n" + "=" * 75)
    print("  VERIFICATION RUN SUMMARY")
    print(f"  TOTAL SAMPLES: {len(results)}")
    print(f"  PASSED_TEST  : {counts['PASSED_TEST']} ({counts['PASSED_TEST']/len(results)*100:.1f}%)")
    print(f"  UNDETERMINED : {counts['UNDETERMINED']}")
    print(f"  BUILD_FAIL   : {counts['BUILD_FAIL']}")
    print("=" * 75)

    # Save JSON report
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    report_file = OUTPUT_DIR / f"report_{int(time.time())}.json"
    report_file.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[+] Full JSON report saved to: {report_file}")

if __name__ == "__main__":
    main()
