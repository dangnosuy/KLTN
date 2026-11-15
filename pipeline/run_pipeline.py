#!/usr/bin/env python3
"""
Unified Multi-Layer Malware Detection Orchestrator
Evaluates samples across 3 layers (Signature, ML, Dynamic) and 8 engines:
  Layer 1 (Signature) : ClamAV, YARA
  Layer 2 (ML)        : SOREL-20M, EMBER 2024, MalConv
  Layer 3 (Dynamic)   : Elastic Defend EDR, Wazuh EDR
  Windows Defender    : Monolithic Host AV/EDR (Stage 1: 10s Static Wait -> Stage 2: 20s Runtime)

Usage:
  python3 pipeline/run_pipeline.py <file_or_dir> [--output-dir pipeline/reports] [--skip-behavior]
"""
import os
import sys
import time
import json
import shutil
import subprocess
import argparse
import requests
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path("/home/dangnosuy/Documents/UIT/KLTN")
sys.path.insert(0, str(BASE_DIR / "pipeline"))

from local_engines import LocalDetectionSuite

SHARED_PAYLOADS = BASE_DIR / "shared_payloads"
SERVER_STATUS_URL = "http://127.0.0.1:8002/api/v1/status"
SESSION_QUERY_URL = "http://127.0.0.1:8002/api/v1/session"


def check_server_health():
    try:
        r = requests.get(SERVER_STATUS_URL, timeout=3)
        return r.status_code == 200
    except Exception:
        return False


def wait_for_vm_evaluation(sha256: str, expected_status: str = None, timeout_seconds: int = 90) -> dict:
    """Poll unified_server for completed Windows VM evaluation."""
    start_time = time.time()
    url = f"{SESSION_QUERY_URL}/{sha256}"
    expected_desc = expected_status or "COMPLETED"
    print(f"[*] Awaiting Windows VM evaluation results [{expected_desc}] (timeout: {timeout_seconds}s)...")

    while time.time() - start_time < timeout_seconds:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                sess = r.json()
                status = sess.get("status")
                win_def = sess.get("windows_defender") or {}

                if expected_status:
                    if status == expected_status:
                        print(f"[+] VM evaluation phase '{expected_status}' completed and synchronized.")
                        return sess
                    elif expected_status == "COMPLETED_BINHTHUONG" and (win_def.get("stage") == "STATIC" or sess.get("defender_static", {}).get("status") == "QUARANTINED"):
                        print("[+] File was statically quarantined by Defender on VM.")
                        return sess
                else:
                    if status in ("COMPLETED", "COMPLETED_BINHTHUONG", "COMPLETED_ELASTIC", "COMPLETED_WAZUH") or win_def.get("stage") == "STATIC":
                        print("[+] VM evaluation completed and synchronized.")
                        return sess
                    elif sess.get("defender_static", {}).get("status") == "QUARANTINED":
                        print("[+] File was statically quarantined by Defender on VM.")
                        return sess
        except Exception:
            pass
        time.sleep(3)

    print(f"[!] Warning: Timeout ({timeout_seconds}s) reached while waiting for VM session {sha256[:8]}.")
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


def switch_vm_snapshot(snapshot_name: str, timeout: int = 90) -> bool:
    """Revert VMware VM to specified snapshot and wait for boot."""
    print(f"\n[*] Switching VM to snapshot '{snapshot_name}'...")
    cmd = ["/home/dangnosuy/Documents/UIT/KLTN/switch-snapshot.sh", snapshot_name]
    subprocess.run(cmd, check=True)

    start = time.time()
    vmx = "/home/dangnosuy/vmware/Windows 11 x64/Windows 11 x64.vmx"
    vm_pass = "dangnosuy"
    print(f"[*] Waiting for Windows VM to initialize and acquire IP (timeout: {timeout}s)...")
    while time.time() - start < timeout:
        res = subprocess.run(["vmrun", "-T", "ws", "-vp", vm_pass, "getGuestIPAddress", vmx], capture_output=True, text=True)
        if res.returncode == 0 and "192.168." in res.stdout:
            print(f"[+] VM ready with IP {res.stdout.strip()}. Waiting 15s for agent & services to settle...")
            time.sleep(15)
            return True
        time.sleep(3)
    print(f"[!] Warning: Timeout waiting for VM IP.")
    return False


def ensure_host_services(phase: str):
    """Verify and ensure required host service stack is active."""
    if phase == "elastic":
        print("[*] Ensuring host service stack: ELASTIC (port 9201 & 8220)...")
        try:
            r = requests.get("https://localhost:9201", auth=("elastic", "UXZCvzc5BNI_J1k6-z+2"), verify=False, timeout=2)
            if r.status_code == 200:
                print("[+] Elasticsearch is up and responding on port 9201.")
                return True
        except Exception:
            pass
        subprocess.run(["sudo", "-n", "systemctl", "start", "elasticsearch", "elastic-agent"], check=True)
        for _ in range(15):
            try:
                r = requests.get("https://localhost:9201", auth=("elastic", "UXZCvzc5BNI_J1k6-z+2"), verify=False, timeout=2)
                if r.status_code == 200:
                    print("[+] Elasticsearch is up and responding on port 9201.")
                    return True
            except Exception:
                pass
            time.sleep(2)
    elif phase == "wazuh":
        print("[*] Ensuring host service stack: WAZUH (port 9200)...")
        try:
            r = requests.get("https://127.0.0.1:9200", auth=("admin", "aQm6A86sgKiEwmOHJ*uT*4vLYqkPzz*g"), verify=False, timeout=2)
            if r.status_code == 200:
                print("[+] Wazuh Indexer is up and responding on port 9200.")
                return True
        except Exception:
            pass
        subprocess.run(["sudo", "-n", "systemctl", "start", "wazuh-indexer", "wazuh-manager"], check=True)
        for _ in range(15):
            try:
                r = requests.get("https://127.0.0.1:9200", auth=("admin", "aQm6A86sgKiEwmOHJ*uT*4vLYqkPzz*g"), verify=False, timeout=2)
                if r.status_code == 200:
                    print("[+] Wazuh Indexer is up and responding on port 9200.")
                    return True
            except Exception:
                pass
            time.sleep(2)
    return True


def evaluate_sample_in_snapshot(file_path: Path, sha256: str, phase_name: str, timeout: int = 180) -> dict:
    """Execute sample inside specified VM snapshot and capture results."""
    try:
        requests.post("http://127.0.0.1:8002/api/v1/phase", json={"phase": phase_name, "sha256": sha256}, timeout=3)
    except Exception:
        pass

    shared_dest = SHARED_PAYLOADS / file_path.name
    print(f"[+] Dropping payload into SMB share for phase '{phase_name}': {shared_dest}")
    try:
        if shared_dest.exists():
            shared_dest.unlink()
            time.sleep(0.5)
    except Exception:
        pass
    shutil.copy2(file_path, shared_dest)
    try:
        os.utime(shared_dest, None)
    except Exception:
        pass

    expected = f"COMPLETED_{phase_name.upper()}"
    sess = wait_for_vm_evaluation(sha256, expected_status=expected, timeout_seconds=timeout)

    try:
        if shared_dest.exists():
            shared_dest.unlink()
    except Exception:
        pass

    return sess


def compile_summary(report: dict) -> dict:
    """Calculate multi-layer detection rates and evasion statistics across 8 engines."""
    l1 = report.get("layer1_signature", {})
    l2 = report.get("layer2_machine_learning", {})
    l3 = report.get("layer3_behavior", {})
    win_def = report.get("windows_defender", {})

    sig_engines = {
        "clamav": bool(l1.get("clamav", {}).get("detected")),
        "yara": bool(l1.get("yara", {}).get("detected"))
    }

    ml_engines = {
        "sorel20m": bool(l2.get("sorel20m", {}).get("detected")),
        "ember2024": bool(l2.get("ember2024", {}).get("detected")),
        "malconv": bool(l2.get("malconv", {}).get("detected"))
    }

    edr_engines = {
        "elastic_defend": bool(l3.get("elastic_defend_edr", {}).get("behavior_detected")),
        "wazuh_defend": bool(l3.get("wazuh_edr", {}).get("detected"))
    }

    defender_engine = {
        "windows_defender": bool(win_def.get("detected"))
    }

    total_sig_det = sum(1 for v in sig_engines.values() if v)
    total_ml_det = sum(1 for v in ml_engines.values() if v)
    total_edr_det = sum(1 for v in edr_engines.values() if v)
    total_def_det = 1 if win_def.get("detected") else 0

    total_engines = len(sig_engines) + len(ml_engines) + len(edr_engines) + len(defender_engine)
    total_detected = total_sig_det + total_ml_det + total_edr_det + total_def_det
    total_evaded = total_engines - total_detected
    bypass_pct = round((total_evaded / total_engines) * 100.0, 1)

    if total_detected == 0:
        verdict = "FULLY_EVADED"
    elif total_detected <= 2:
        verdict = "HIGHLY_EVASIVE"
    elif total_detected < total_engines:
        verdict = "PARTIALLY_EVADED"
    else:
        verdict = "BLOCKED"

    return {
        "total_layers": 3,
        "total_engines": total_engines,
        "detections": {
            "signature_engines": {"total": len(sig_engines), "detected": total_sig_det, "evaded": len(sig_engines) - total_sig_det, "breakdown": sig_engines},
            "ml_engines": {"total": len(ml_engines), "detected": total_ml_det, "evaded": len(ml_engines) - total_ml_det, "breakdown": ml_engines},
            "edr_engines": {"total": len(edr_engines), "detected": total_edr_det, "evaded": len(edr_engines) - total_edr_det, "breakdown": edr_engines},
            "windows_defender": {"total": 1, "detected": total_def_det, "evaded": 1 - total_def_det, "stage": win_def.get("stage", "NONE"), "status": win_def.get("status", "CLEAN")}
        },
        "overall_detection_count": total_detected,
        "overall_evasion_count": total_evaded,
        "bypass_rate_pct": bypass_pct,
        "overall_verdict": verdict
    }


def print_cli_report(res: dict):
    meta = res.get("metadata", {})
    l1 = res.get("layer1_signature", {})
    l2 = res.get("layer2_machine_learning", {})
    l3 = res.get("layer3_behavior", {})
    wd = res.get("windows_defender", {})
    sm = res.get("summary", {})

    print("\n" + "=" * 90)
    print(f"SAMPLE EVALUATION REPORT: {meta.get('filename')} ({meta.get('file_size_bytes', 0):,} bytes)")
    print(f"SHA256: {meta.get('sha256')}")
    print("=" * 90)

    row_fmt = "  {:<28} | {:<12} | {:<10} | {:<32}"
    print(row_fmt.format("DETECTOR ENGINE", "LAYER", "VERDICT", "KEY DETAILS / THREAT"))
    print("  " + "-" * 86)

    # Layer 1: Signatures
    c = l1.get("clamav", {})
    c_ver = "🔴 MALWARE" if c.get("detected") else "🟢 BENIGN"
    print(row_fmt.format("ClamAV", "Signature", c_ver, str(c.get("threat_name") or "Clean")[:32]))

    y = l1.get("yara", {})
    y_ver = "🔴 MALWARE" if y.get("detected") else "🟢 BENIGN"
    y_rules = ", ".join(y.get("matched_rules", [])) if y.get("matched_rules") else "No matches"
    print(row_fmt.format("YARA Rules", "Signature", y_ver, y_rules[:32]))

    # Layer 2: Machine Learning
    s = l2.get("sorel20m", {})
    s_ver = "🔴 MALWARE" if s.get("detected") else "🟢 BENIGN"
    print(row_fmt.format("SOREL-20M (DNN)", "ML-Model", s_ver, f"Prob: {s.get('score')}"))

    e = l2.get("ember2024", {})
    e_ver = "🔴 MALWARE" if e.get("detected") else "🟢 BENIGN"
    print(row_fmt.format("EMBER 2024 (LGBM)", "ML-Model", e_ver, f"Score: {e.get('score')}"))

    m = l2.get("malconv", {})
    m_ver = "🔴 MALWARE" if m.get("detected") else "🟢 BENIGN"
    print(row_fmt.format("MalConv (CNN)", "ML-Model", m_ver, f"RawPred: {m.get('raw_pred')}"))

    # Layer 3: Dynamic EDRs
    ed = l3.get("elastic_defend_edr", {})
    ed_ver = "🔴 MALWARE" if ed.get("behavior_detected") else "🟢 BENIGN"
    ed_det = f"{ed.get('behavior_alert_count', 0)} beh, {ed.get('file_alert_count', 0)} file"
    print(row_fmt.format("Elastic Defend EDR", "Dynamic-EDR", ed_ver, ed_det))

    wz = l3.get("wazuh_edr", {})
    wz_ver = "🔴 MALWARE" if wz.get("detected") else "🟢 BENIGN"
    wz_det = f"{wz.get('suspicious_alert_count', 0)} suspicious / {wz.get('total_alert_count', 0)} total"
    print(row_fmt.format("Wazuh EDR (Sysmon)", "Dynamic-EDR", wz_ver, wz_det))

    # Dedicated Windows Defender Suite (Stage 1 Wait 10s -> Stage 2 Run 20s)
    wd_ver = "🔴 MALWARE" if wd.get("detected") else "🟢 BENIGN"
    stage = wd.get("stage", "NONE")
    th = wd.get("threat_name") or wd.get("status") or "Clean"
    wd_details = f"[{stage}] {th}"
    print(row_fmt.format("Windows Defender", "Host-AV/EDR", wd_ver, str(wd_details)[:32]))

    print("  " + "-" * 86)
    print(f"OVERALL VERDICT : {sm.get('overall_verdict')} (Bypass Rate: {sm.get('bypass_rate_pct')}%)")
    print(f"DETECTION STATS : Detected by {sm.get('overall_detection_count')}/{sm.get('total_engines')} engines across all layers.")
    print("=" * 90 + "\n")


def process_single_file(file_path: Path, suite: LocalDetectionSuite, output_dir: Path, skip_behavior: bool = False, multi_snapshot: bool = False) -> dict:
    print(f"\n[*] Evaluating target sample: {file_path.name}")

    # 1. Local Linux Execution (Phase 1 + 2)
    local_data = suite.evaluate_file(str(file_path))
    sha256 = local_data["metadata"]["sha256"]

    report = {
        "metadata": {
            **local_data["metadata"],
            "evaluated_at": datetime.now(timezone.utc).isoformat()
        },
        "layer1_signature": local_data["layer1_signature"],
        "layer2_machine_learning": local_data["layer2_machine_learning"],
        "layer3_behavior": {
            "execution_telemetry": {},
            "elastic_defend_edr": {"behavior_detected": False, "behavior_alert_count": 0, "file_detected": False, "alerts": []},
            "wazuh_edr": {"detected": False, "suspicious_alert_count": 0, "total_alert_count": 0, "suspicious_alerts": []}
        },
        "windows_defender": {
            "detected": False,
            "stage": "SKIPPED",
            "status": "SKIPPED",
            "threat_name": None,
            "events": []
        }
    }

    # 2. Windows VM Execution (Phase 3)
    if not skip_behavior:
        if not check_server_health():
            print("[-] Error: Unified server (port 8002) is not responding. Start pipeline/unified_server.py first!")
            report["windows_defender"]["status"] = "SERVER_OFFLINE"
        elif multi_snapshot:
            print("\n" + "=" * 80)
            print(f"[*] STARTING MULTI-SNAPSHOT 3-PHASE EVALUATION FOR: {file_path.name}")
            print("=" * 80)

            # --- Phase 1: binhthuong (Windows Defender Monolithic) ---
            print("\n[>>>] PHASE 1/3: Windows Defender Sandbox (Snapshot 'binhthuong')")
            switch_vm_snapshot("binhthuong")
            sess_binhthuong = evaluate_sample_in_snapshot(file_path, sha256, "binhthuong")
            if sess_binhthuong:
                if sess_binhthuong.get("windows_defender"):
                    report["windows_defender"] = sess_binhthuong["windows_defender"]
                elif sess_binhthuong.get("defender_static") or sess_binhthuong.get("defender_behavior"):
                    ds = sess_binhthuong.get("defender_static", {})
                    db = sess_binhthuong.get("defender_behavior", {})
                    det = ds.get("detected", False) or db.get("detected", False)
                    stage = "STATIC" if ds.get("detected") else ("BEHAVIOR" if db.get("detected") else "NONE")
                    report["windows_defender"] = {
                        "detected": det,
                        "stage": stage,
                        "status": ds.get("status") or ("DETECTED_BEHAVIOR" if det else "CLEAN"),
                        "threat_name": ds.get("threat_name") or (db.get("events", [{}])[0].get("ThreatName") if db.get("events") else None),
                        "events": ds.get("events", []) + db.get("events", [])
                    }
                if sess_binhthuong.get("execution_telemetry"):
                    report["layer3_behavior"]["execution_telemetry"] = sess_binhthuong["execution_telemetry"]

            # --- Phase 2: elastic (Elastic Defend EDR) ---
            print("\n[>>>] PHASE 2/3: Elastic Defend EDR Sandbox (Snapshot 'elastic')")
            ensure_host_services("elastic")
            switch_vm_snapshot("elastic")
            sess_elastic = evaluate_sample_in_snapshot(file_path, sha256, "elastic")
            if sess_elastic and sess_elastic.get("elastic_defend"):
                report["layer3_behavior"]["elastic_defend_edr"] = sess_elastic["elastic_defend"]

            # --- Phase 3: wazuh (Wazuh EDR & Sysmon) ---
            print("\n[>>>] PHASE 3/3: Wazuh EDR Sandbox (Snapshot 'wazuh')")
            ensure_host_services("wazuh")
            switch_vm_snapshot("wazuh")
            sess_wazuh = evaluate_sample_in_snapshot(file_path, sha256, "wazuh")
            if sess_wazuh and sess_wazuh.get("wazuh_defend"):
                report["layer3_behavior"]["wazuh_edr"] = sess_wazuh["wazuh_defend"]

        else:
            # Single VM execution (Current snapshot)
            shared_dest = SHARED_PAYLOADS / file_path.name
            print(f"[+] Dropping payload into SMB share: {shared_dest}")
            try:
                if shared_dest.exists():
                    shared_dest.unlink()
                    time.sleep(0.5)
            except Exception:
                pass
            shutil.copy2(file_path, shared_dest)
            try:
                os.utime(shared_dest, None)
            except Exception:
                pass

            # Wait for VM to finish static scan + dynamic execution
            vm_session = wait_for_vm_evaluation(sha256, timeout_seconds=180)

            # Cleanup dropped payload from SMB share after evaluation
            try:
                if shared_dest.exists():
                    shared_dest.unlink()
            except Exception:
                pass

            if vm_session:
                # Merge Unified Windows Defender
                if vm_session.get("windows_defender"):
                    report["windows_defender"] = vm_session["windows_defender"]
                elif vm_session.get("defender_static") or vm_session.get("defender_behavior"):
                    ds = vm_session.get("defender_static", {})
                    db = vm_session.get("defender_behavior", {})
                    det = ds.get("detected", False) or db.get("detected", False)
                    stage = "STATIC" if ds.get("detected") else ("BEHAVIOR" if db.get("detected") else "NONE")
                    report["windows_defender"] = {
                        "detected": det,
                        "stage": stage,
                        "status": ds.get("status") or ("DETECTED_BEHAVIOR" if det else "CLEAN"),
                        "threat_name": ds.get("threat_name") or (db.get("events", [{}])[0].get("ThreatName") if db.get("events") else None),
                        "events": ds.get("events", []) + db.get("events", [])
                    }

                # Merge Elastic Defend
                if vm_session.get("elastic_defend"):
                    report["layer3_behavior"]["elastic_defend_edr"] = vm_session["elastic_defend"]

                # Merge Wazuh EDR
                if vm_session.get("wazuh_defend"):
                    report["layer3_behavior"]["wazuh_edr"] = vm_session["wazuh_defend"]

                # Merge Execution Telemetry
                if vm_session.get("execution_telemetry"):
                    report["layer3_behavior"]["execution_telemetry"] = vm_session["execution_telemetry"]

    # 3. Calculate Summary & Metrics
    report["summary"] = compile_summary(report)

    # 4. Save JSON Report
    out_filename = f"{file_path.stem}_{sha256[:8]}.json"
    out_path = output_dir / out_filename
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)
    print(f"[+] Unified report saved to: {out_path}")

    print_cli_report(report)
    return report


def main():
    parser = argparse.ArgumentParser(description="Unified Multi-Layer Malware Detection Pipeline Orchestrator")
    parser.add_argument("target", help="Path to PE executable (.exe) or directory of samples")
    parser.add_argument("--output-dir", default=str(BASE_DIR / "pipeline" / "reports"), help="Output directory for JSON reports")
    parser.add_argument("--skip-behavior", action="store_true", help="Run only local Signature and ML engines (skip Windows VM)")
    parser.add_argument("--multi-snapshot", action="store_true", help="Automatically cycle through all 3 snapshots: binhthuong, elastic, wazuh")
    args = parser.parse_args()

    target_path = Path(args.target).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if not target_path.exists():
        print(f"Error: Target path '{target_path}' does not exist.")
        sys.exit(1)

    suite = LocalDetectionSuite()

    targets = []
    if target_path.is_dir():
        for root, _, files in os.walk(target_path):
            for f in sorted(files):
                if f.lower().endswith(".exe"):
                    targets.append(Path(root) / f)
    else:
        targets.append(target_path)

    print(f"\n[*] Pipeline ready. Processing {len(targets)} sample(s)...")

    results = []
    for idx, sample in enumerate(targets, 1):
        print(f"\n[{idx}/{len(targets)}] ----------------------------------------------------")
        res = process_single_file(sample, suite, output_dir, skip_behavior=args.skip_behavior, multi_snapshot=args.multi_snapshot)
        results.append(res)
        # Settle buffer between samples when executing live behavior
        if not args.skip_behavior and len(targets) > 1:
            print("[*] Cooling down 5s before next sample...")
            time.sleep(5)

    print(f"\n[+] All evaluations completed. Full reports stored in {output_dir}")


if __name__ == "__main__":
    main()
