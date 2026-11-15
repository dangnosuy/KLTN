import os
import shutil
import time
import json
import hashlib
import threading
import subprocess
import requests
from datetime import datetime, timezone
from watchdog.observers.polling import PollingObserver as Observer
from watchdog.events import FileSystemEventHandler

# --- CONFIGURATION ---
SHARED_FOLDER = r"\\192.168.183.1\shared_payloads"
SMB_USER = "dangnosuy"
SMB_PASS = "dangnosuy"
STATIC_DROP_DIR = r"C:\Payload_Testing"
DYNAMIC_DROP_DIR = r"C:\Elastic_Testing"
LINUX_BASE_URL = "http://192.168.183.1:8002"

STATIC_API_URL = f"{LINUX_BASE_URL}/api/v1/defender_static"
BEHAVIOR_API_URL = f"{LINUX_BASE_URL}/api/v1/behavior_report"

EXECUTION_TIMEOUT = 20  # Seconds to observe dynamic behavior
STATIC_WAIT_TIMEOUT = 10  # Seconds to hang on disk for static on-access inspection

os.makedirs(STATIC_DROP_DIR, exist_ok=True)
os.makedirs(DYNAMIC_DROP_DIR, exist_ok=True)
PROCESSED_ITEMS = {}  # filename -> (mtime, size)
PROCESSING_LOCK = threading.Lock()


def calc_file_hashes(filepath):
    """Compute sha256 and md5 on Windows."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        return hashlib.md5(data).hexdigest(), hashlib.sha256(data).hexdigest(), len(data)
    except Exception:
        return "N/A", "N/A", 0


def mount_smb_share():
    """Mount SMB share with stored credentials via net use."""
    cmd = f'net use "{SHARED_FOLDER}" /user:{SMB_USER} {SMB_PASS} /persistent:yes'
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if res.returncode == 0 or "already" in res.stderr.lower() or "already" in res.stdout.lower():
        print(f"[+] SMB authenticated: {SHARED_FOLDER}")
    else:
        print(f"[!] Warning connecting SMB: {res.stderr.strip() or res.stdout.strip()}")


def check_smb_access():
    """Verify read access to the SMB share."""
    try:
        items = os.listdir(SHARED_FOLDER)
        print(f"[+] SMB share accessible ({len(items)} items currently present).")
        return True
    except Exception as e:
        print(f"[-] ERROR: Cannot access SMB share {SHARED_FOLDER}: {e}")
        return False


def query_mpcomputer_status():
    """Retrieve Defender Engine configuration and signature versions."""
    ps_script = """
    $sig = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($sig) {
        [PSCustomObject]@{
            AntivirusSignatureVersion     = $sig.AntivirusSignatureVersion
            AntivirusSignatureLastUpdated = if ($sig.AntivirusSignatureLastUpdated) { $sig.AntivirusSignatureLastUpdated.ToString("o") } else { $null }
            EngineVersion                 = $sig.EngineVersion
            ProductVersion                = $sig.AMProductVersion
            RealTimeProtectionEnabled     = $sig.RealTimeProtectionEnabled
            BehaviorMonitorEnabled        = $sig.BehaviorMonitorEnabled
            IoavProtectionEnabled         = $sig.IoavProtectionEnabled
        } | ConvertTo-Json
    }
    """
    try:
        proc = subprocess.run(["powershell", "-NoProfile", "-Command", ps_script], capture_output=True, text=True)
        out = proc.stdout.strip()
        return json.loads(out) if out else {}
    except Exception:
        return {}


DEFENDER_INFO = query_mpcomputer_status()


def trigger_defender_static_scan(target_path):
    """Trigger Defender static signature on-access & on-demand scan."""
    clean_path = target_path.replace("'", "''")
    ps_cmd = f"""
    $p = '{clean_path}'
    if (Test-Path $p) {{
        try {{ [System.IO.File]::ReadAllBytes($p) | Out-Null }} catch {{ }}
        Start-MpScan -ScanType CustomScan -ScanPath $p -ErrorAction SilentlyContinue | Out-Null
    }}
    """
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, timeout=15)
    except Exception:
        pass


def query_defender_events(target_filename, detection_type_filter=None, search_window_seconds=60):
    """Query Defender operational log (Event ID 1116/1117)."""
    clean_filename = target_filename.replace("'", "''")
    ps_script = f"""
    $startTime = (Get-Date).AddSeconds(-{search_window_seconds})
    $events = Get-WinEvent -FilterHashtable @{{
        LogName = 'Microsoft-Windows-Windows Defender/Operational'
        Id = 1116, 1117
        StartTime = $startTime
    }} -ErrorAction SilentlyContinue

    $results = @()
    foreach ($e in $events) {{
        $xml = [xml]$e.ToXml()
        $dataMap = @{{}}
        foreach ($item in $xml.Event.EventData.Data) {{
            $name = $item.GetAttribute('Name')
            if ($name) {{
                $val = if ($item.'#text') {{ $item.'#text' }} else {{ $item.InnerText }}
                $dataMap[$name] = $val
            }}
        }}

        $path = $dataMap['Path']
        $threatName = $dataMap['Threat Name']
        $detType = $dataMap['Detection Type Name']

        if ($path -like "*{clean_filename}*" -or ($threatName -and ($path -like "*Payload_Testing*" -or $path -like "*Elastic_Testing*"))) {{
            $results += [PSCustomObject]@{{
                Id                          = $e.Id
                TimeCreated                 = $e.TimeCreated.ToString("o")
                ThreatName                  = $threatName
                Severity                    = $dataMap['Severity Name']
                SeverityID                  = $dataMap['Severity ID']
                Category                    = $dataMap['Category Name']
                CategoryID                  = $dataMap['Category ID']
                DetectionType               = $detType
                DetectionOrigin             = $dataMap['Detection Origin Type']
                Action                      = $dataMap['Action Name']
                ActionID                    = $dataMap['Action ID']
                Path                        = $path
                ProcessName                 = $dataMap['Process Name']
                ProcessID                   = $dataMap['Process ID']
                EngineVersion               = $dataMap['Engine Version']
                SignatureVersion            = $dataMap['Security Intelligence Version']
                ProductVersion              = $dataMap['Product Version']
                ErrorCode                   = $dataMap['Error Code']
            }}
        }}
    }}
    $results | ConvertTo-Json -Depth 4
    """
    try:
        proc = subprocess.run(["powershell", "-NoProfile", "-Command", ps_script], capture_output=True, text=True)
        out = proc.stdout.strip()
        if out:
            parsed = json.loads(out)
            items = [parsed] if isinstance(parsed, dict) else parsed
            dedup = []
            seen = set()
            for it in items:
                # Apply optional filter (e.g. Behavior vs Concrete)
                if detection_type_filter and detection_type_filter.lower() not in str(it.get("DetectionType", "")).lower():
                    continue
                key = (it.get("Id"), it.get("ThreatName"), it.get("DetectionType"), it.get("Action"))
                if key not in seen:
                    seen.add(key)
                    dedup.append(it)
            return dedup
        return []
    except Exception as err:
        return [{"error": str(err)}]


def ensure_decoy_notepad():
    """Ensure at least one decoy notepad process is running for injector payloads."""
    try:
        proc = subprocess.run(["powershell", "-NoProfile", "-Command", "Get-Process notepad -ErrorAction SilentlyContinue"], capture_output=True, text=True)
        if not proc.stdout.strip():
            subprocess.Popen(["notepad.exe"])
            time.sleep(1)
    except Exception:
        pass


def setup_decoy_files(sandbox_path):
    decoys = {
        "decoy_financial.xlsx": b"SAMPLE_EXCEL_FINANCIAL_REPORTS_CONTENT_2026",
        "decoy_passwords.txt": b"admin:SuperSecretPassword123!\nsystem:InternalPass2026",
        "decoy_photo.jpg": b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00FAKE_JPEG_IMAGE_DATA",
        "decoy_contract.docx": b"PK\x03\x04CONFIDENTIAL_BUSINESS_CONTRACT_DATA_BENIGN"
    }
    initial_state = {}
    for name, content in decoys.items():
        fpath = os.path.join(sandbox_path, name)
        if not os.path.exists(fpath):
            with open(fpath, "wb") as f:
                f.write(content)
        initial_state[name] = {"size": os.path.getsize(fpath), "mtime": os.path.getmtime(fpath)}
    return initial_state


def check_decoy_changes(sandbox_path, initial_state, payload_filename):
    created = []
    modified = []
    deleted = []
    try:
        current_files = set(os.listdir(sandbox_path))
    except Exception:
        current_files = set()
    initial_files = set(initial_state.keys())

    for orig in initial_files:
        if orig not in current_files:
            deleted.append(orig)
        else:
            orig_path = os.path.join(sandbox_path, orig)
            try:
                cur_size = os.path.getsize(orig_path)
                cur_mtime = os.path.getmtime(orig_path)
                if cur_size != initial_state[orig]["size"] or cur_mtime != initial_state[orig]["mtime"]:
                    modified.append(orig)
            except Exception:
                pass

    for f in current_files:
        if f != payload_filename and f not in initial_files:
            created.append(f)

    return {"created": created, "modified": modified, "deleted": deleted}


def query_child_processes(parent_pid):
    ps = f"""
    Get-CimInstance Win32_Process -Filter "ParentProcessId = {parent_pid}" -ErrorAction SilentlyContinue |
    Select-Object ProcessId, Name, CommandLine | ConvertTo-Json
    """
    try:
        proc = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True)
        out = proc.stdout.strip()
        if out:
            p = json.loads(out)
            return [p] if isinstance(p, dict) else p
        return []
    except Exception:
        return []


def query_network_connections(pids):
    if not pids:
        return []
    pid_list = ",".join(str(p) for p in pids)
    ps = f"""
    Get-NetTCPConnection -OwningProcess {pid_list} -ErrorAction SilentlyContinue |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State | ConvertTo-Json
    """
    try:
        proc = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True)
        out = proc.stdout.strip()
        if out:
            p = json.loads(out)
            return [p] if isinstance(p, dict) else p
        return []
    except Exception:
        return []


class UnifiedPayloadHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            self.handle_payload(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.handle_payload(event.src_path)

    def handle_payload(self, source_path):
        if not os.path.exists(source_path):
            return

        filename = os.path.basename(source_path)
        if filename.startswith("~") or filename.endswith(".tmp"):
            return

        with PROCESSING_LOCK:
            try:
                mtime = os.path.getmtime(source_path)
                size = os.path.getsize(source_path)
            except Exception:
                return

            # Avoid reprocessing identical file without modifications
            prev = PROCESSED_ITEMS.get(filename)
            if prev and prev == (mtime, size):
                return

            # Wait briefly for file write to complete
            time.sleep(1)
            try:
                cur_size = os.path.getsize(source_path)
                cur_mtime = os.path.getmtime(source_path)
            except Exception:
                return

            PROCESSED_ITEMS[filename] = (cur_mtime, cur_size)

            print("\n" + "=" * 75)
            print(f"[*] NEW PAYLOAD RECEIVED FOR FULL EVALUATION: {filename} ({cur_size} bytes)")
            print("=" * 75)

            # Non-exe files (e.g. .dll, .bin, .dat): stage directly into dynamic dir and return
            if not filename.lower().endswith(".exe"):
                target_dest = os.path.join(DYNAMIC_DROP_DIR, filename)
                try:
                    shutil.copy2(source_path, target_dest)
                    print(f"[+] Staged supporting asset to: {target_dest}")
                except Exception as e:
                    print(f"[-] Staging error: {e}")
                return

            md5_val, sha256_val, f_size = calc_file_hashes(source_path)

            # =========================================================================
            # STAGE 1: WINDOWS DEFENDER STATIC ON-DISK HANG (10s)
            # =========================================================================
            print(f"\n--- [Stage 1] Staging file on disk & waiting {STATIC_WAIT_TIMEOUT}s for Defender Static Scan ---")
            sandbox_dest = os.path.join(DYNAMIC_DROP_DIR, filename)
            try:
                shutil.copy2(source_path, sandbox_dest)
            except Exception as e:
                print(f"[-] Failed to copy to sandbox staging: {e}")
                return

            # Hang file on disk for 10s for Windows Defender on-access / real-time inspection
            print(f"[*] File placed at {sandbox_dest}. Waiting {STATIC_WAIT_TIMEOUT}s on disk...")
            time.sleep(STATIC_WAIT_TIMEOUT)

            # Check if file survived the 10s static hang
            file_survived = os.path.exists(sandbox_dest)
            static_events = query_defender_events(filename, search_window_seconds=STATIC_WAIT_TIMEOUT + 5)
            static_detected = (not file_survived) or len(static_events) > 0

            if static_detected:
                threat_name = static_events[0].get("ThreatName") if static_events else "Quarantined"
                status_str = "QUARANTINED" if not file_survived else "DETECTED_BUT_PRESENT"
                print(f"[!] Windows Defender STATIC detection triggered! Threat: {threat_name} | Status: {status_str}")

                report_payload = {
                    "filename": filename,
                    "sha256": sha256_val,
                    "md5": md5_val,
                    "file_size_bytes": f_size,
                    "execution_status": f"STATIC_{status_str}",
                    "exec_start_iso": datetime.now(timezone.utc).isoformat(),
                    "exec_end_iso": datetime.now(timezone.utc).isoformat(),
                    "main_pid": None,
                    "child_processes": [],
                    "network_connections": [],
                    "decoy_file_modifications": {},
                    "windows_defender": {
                        "detected": True,
                        "stage": "STATIC",
                        "status": status_str,
                        "threat_name": threat_name,
                        "events": static_events,
                        "system_info": DEFENDER_INFO
                    }
                }

                try:
                    r = requests.post(BEHAVIOR_API_URL, json=report_payload, timeout=10)
                    print(f"[+] Reported static quarantine to Linux server: HTTP {r.status_code}")
                except Exception as e:
                    print(f"[-] Failed to report static detection: {e}")

                try:
                    if os.path.exists(sandbox_dest):
                        os.remove(sandbox_dest)
                except Exception:
                    pass
                print("=" * 75 + "\n")
                return

            print(f"[+] File survived {STATIC_WAIT_TIMEOUT}s static inspection clean. Proceeding to Stage 2...")

            # =========================================================================
            # STAGE 2: DYNAMIC BEHAVIOR EXECUTION (SANDBOX + EDRs + DEFENDER BEHAVIOR)
            # =========================================================================
            print("\n--- [Stage 2] Dynamic Behavior & Runtime EDR Execution (20s) ---")
            decoy_state = setup_decoy_files(DYNAMIC_DROP_DIR)
            ensure_decoy_notepad()
            exec_start_iso = datetime.now(timezone.utc).isoformat()
            print(f"[*] Executing target ({EXECUTION_TIMEOUT}s timeout, window start: {exec_start_iso})...")

            start_time = time.time()
            child_procs = []
            net_conns = []
            all_monitored_pids = set()
            proc = None

            try:
                proc = subprocess.Popen(
                    [sandbox_dest],
                    cwd=DYNAMIC_DROP_DIR,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                all_monitored_pids.add(proc.pid)
                print(f"[+] Process started with PID: {proc.pid}")
            except Exception as e:
                print(f"[-] Execution error: {e}")

            exec_status = "UNKNOWN"

            if proc:
                while time.time() - start_time < EXECUTION_TIMEOUT:
                    ret = proc.poll()
                    if ret is not None:
                        if ret == 0:
                            exec_status = "EXITED_NORMAL (Code: 0)"
                        elif ret in (-1073741819, 3221225477):
                            exec_status = "CRASHED_OR_BLOCKED (Access Violation)"
                        elif ret == 3221226505:
                            exec_status = "CRASHED (Stack Buffer Overrun / FastFail)"
                        else:
                            exec_status = f"TERMINATED (Exit code: {ret})"
                        print(f"[*] Process terminated early: {exec_status}")
                        break

                    cps = query_child_processes(proc.pid)
                    if cps:
                        for cp in cps:
                            child_procs.append(cp)
                            all_monitored_pids.add(cp.get("ProcessId"))

                    ncs = query_network_connections(list(all_monitored_pids))
                    if ncs:
                        for nc in ncs:
                            if nc not in net_conns:
                                net_conns.append(nc)

                    time.sleep(1)

                if proc.poll() is None:
                    exec_status = f"SURVIVED_TIMEOUT ({EXECUTION_TIMEOUT}s)"
                    print(f"[*] Process survived {EXECUTION_TIMEOUT}s observation window.")

                # Kill process tree
                try:
                    subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
                except Exception:
                    pass

            exec_end_iso = datetime.now(timezone.utc).isoformat()
            file_mods = check_decoy_changes(DYNAMIC_DROP_DIR, decoy_state, filename)

            # Query Defender events during the dynamic execution window
            def_behavior_events = query_defender_events(filename, search_window_seconds=EXECUTION_TIMEOUT + 5)
            behavior_detected = len(def_behavior_events) > 0
            threat_name = def_behavior_events[0].get("ThreatName") if def_behavior_events else None

            print(f"[+] Dynamic Result: {exec_status} | Defender Behavior Events: {len(def_behavior_events)}")

            behavior_payload = {
                "filename": filename,
                "sha256": sha256_val,
                "md5": md5_val,
                "file_size_bytes": f_size,
                "execution_status": exec_status,
                "exec_start_iso": exec_start_iso,
                "exec_end_iso": exec_end_iso,
                "main_pid": proc.pid if proc else None,
                "child_processes": child_procs,
                "network_connections": net_conns,
                "decoy_file_modifications": file_mods,
                "windows_defender": {
                    "detected": behavior_detected,
                    "stage": "BEHAVIOR" if behavior_detected else "NONE",
                    "status": "DETECTED_BEHAVIOR" if behavior_detected else "CLEAN",
                    "threat_name": threat_name,
                    "events": def_behavior_events,
                    "system_info": DEFENDER_INFO
                }
            }

            try:
                r = requests.post(BEHAVIOR_API_URL, json=behavior_payload, timeout=15)
                print(f"[+] Reported dynamic execution & behavior to Linux: HTTP {r.status_code}")
            except Exception as e:
                print(f"[-] Failed to report behavior telemetry: {e}")

            print("=" * 75 + "\n")


if __name__ == "__main__":
    print(f"[*] Unified Windows Security Agent Active")
    print(f"[*] Shared Folder Monitored : {SHARED_FOLDER}")
    print(f"[*] Static Drop Workspace    : {STATIC_DROP_DIR}")
    print(f"[*] Dynamic Sandbox Workspace: {DYNAMIC_DROP_DIR}")
    print(f"[*] Unified Listener Endpoint: {LINUX_BASE_URL}")

    mount_smb_share()
    check_smb_access()

    event_handler = UnifiedPayloadHandler()
    observer = Observer()
    observer.schedule(event_handler, SHARED_FOLDER, recursive=False)
    observer.start()

    try:
        while True:
            # Active polling fallback: check shared folder directly every 2s
            try:
                if os.path.exists(SHARED_FOLDER):
                    for fname in os.listdir(SHARED_FOLDER):
                        fpath = os.path.join(SHARED_FOLDER, fname)
                        if os.path.isfile(fpath):
                            event_handler.handle_payload(fpath)
            except Exception:
                pass
            time.sleep(2)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
