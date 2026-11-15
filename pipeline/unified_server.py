#!/usr/bin/env python3
"""
Unified Multi-Layer Listener Server (Linux Host)
Binds to 0.0.0.0:8002.
Endpoints:
  - POST /api/v1/defender_static   : Receives Defender static scan log from Windows VM
  - POST /api/v1/behavior_report   : Receives Defender dynamic log & execution telemetry
  - GET  /api/v1/session/<sha256>  : Queries unified session state for CLI orchestrator
  - GET  /api/v1/status            : Healthcheck
"""
import os
import sys
import json
import time
import hashlib
import threading
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

PORT = 8002
SHARED_DIR = "/home/dangnosuy/Documents/UIT/KLTN/shared_payloads"
OUTPUT_DIR = "/home/dangnosuy/Documents/UIT/KLTN/pipeline/reports"

STATIC_OUTPUT_DIR = "/home/dangnosuy/Documents/UIT/KLTN/Signature-base/WinDefen-Signaturebase/static_scan_reports"
BEHAVIOR_OUTPUT_DIR = "/home/dangnosuy/Documents/UIT/KLTN/Behavior-base/behavior_scan_reports"
ELASTIC_OUTPUT_DIR = "/home/dangnosuy/Documents/UIT/KLTN/Elastic-Defend/elastic_scan_reports"
WAZUH_OUTPUT_DIR = "/home/dangnosuy/Documents/UIT/KLTN/Wazuh-Defend/wazuh_scan_reports"

os.makedirs(STATIC_OUTPUT_DIR, exist_ok=True)
os.makedirs(BEHAVIOR_OUTPUT_DIR, exist_ok=True)
os.makedirs(ELASTIC_OUTPUT_DIR, exist_ok=True)
os.makedirs(WAZUH_OUTPUT_DIR, exist_ok=True)

ES_URL = os.getenv("ES_URL", "https://localhost:9201")
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASS = os.getenv("ES_PASS", "UXZCvzc5BNI_J1k6-z+2")
ES_AUTH = (ES_USER, ES_PASS)

WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://127.0.0.1:9200")
WAZUH_USER = os.getenv("WAZUH_USER", "admin")
WAZUH_PASS = os.getenv("WAZUH_PASS", "aQm6A86sgKiEwmOHJ*uT*4vLYqkPzz*g")
WAZUH_AUTH = (WAZUH_USER, WAZUH_PASS)
WAZUH_AGENT_ID = os.getenv("WAZUH_AGENT_ID", "001")
WAZUH_ALERT_INDEX = "wazuh-alerts-4.x-*"

ALERT_INDICES = ["logs-endpoint.alerts-*", ".alerts-security.alerts-default"]
POLL_INTERVAL_SECONDS = 5
MAX_POLL_ATTEMPTS = 6  # 30s total budget

os.makedirs(SHARED_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# In-memory storage for active sessions keyed by sha256
SESSIONS = {}
SESSIONS_LOCK = threading.Lock()


CURRENT_PHASE = "all"


def get_or_create_session(sha256, filename=None, md5=None, size_bytes=0):
    with SESSIONS_LOCK:
        if sha256 not in SESSIONS:
            SESSIONS[sha256] = {
                "sha256": sha256,
                "md5": md5,
                "filename": filename,
                "file_size_bytes": size_bytes,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "windows_defender": None,
                "defender_static": None,
                "defender_behavior": None,
                "elastic_defend": None,
                "wazuh_defend": None,
                "execution_telemetry": None,
                "status": "INITIALIZED"
            }
        elif filename and not SESSIONS[sha256].get("filename"):
            SESSIONS[sha256]["filename"] = filename
        return SESSIONS[sha256]


def calc_file_hashes(filepath):
    if not os.path.exists(filepath):
        return "N/A", "N/A", 0
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    size = os.path.getsize(filepath)
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest(), size


def query_elastic_alerts_once(process_name, time_from, time_to, sha256_hash=None):
    query = {
        "query": {
            "bool": {
                "must": [
                    {
                        "bool": {
                            "should": [
                                {"term": {"process.name": process_name}},
                                {"wildcard": {"process.executable": f"*{process_name}*"}},
                                {"wildcard": {"kibana.alert.reason": f"*{process_name}*"}},
                                {"term": {"file.hash.sha256": sha256_hash or ""}}
                            ],
                            "minimum_should_match": 1
                        }
                    }
                ],
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": time_from,
                                "lte": time_to
                            }
                        }
                    }
                ]
            }
        },
        "sort": [{"@timestamp": "asc"}],
        "size": 100
    }

    hits_by_id = {}
    for idx in ALERT_INDICES:
        try:
            resp = requests.get(
                f"{ES_URL}/{idx}/_search",
                auth=ES_AUTH,
                verify=False,
                json=query,
                timeout=10
            )
            if resp.status_code == 200:
                for h in resp.json().get("hits", {}).get("hits", []):
                    doc_id = (
                        h.get("_source", {}).get("event", {}).get("id")
                        or h.get("_source", {}).get("kibana.alert.uuid")
                        or h.get("_id")
                    )
                    if doc_id not in hits_by_id:
                        hits_by_id[doc_id] = h["_source"]
        except Exception as e:
            print(f"[-] ES query error on {idx}: {e}")

    return list(hits_by_id.values())


def parse_elastic_alert(src):
    proc = src.get("process", {})
    proc_ext = proc.get("Ext", {})
    api_info = proc_ext.get("api", {})
    mem_info = proc_ext.get("memory_region", {})
    thread_ext = proc.get("thread", {}).get("Ext", {})

    mitre_list = []
    for th in src.get("threat", []):
        tactic_name = th.get("tactic", {}).get("name")
        tactic_id = th.get("tactic", {}).get("id")
        for tech in th.get("technique", []):
            tech_name = tech.get("name")
            tech_id = tech.get("id")
            sub_id = None
            if tech.get("subtechnique"):
                sub_id = tech["subtechnique"][0].get("id")
            mitre_list.append({
                "tactic": f"{tactic_name} ({tactic_id})" if tactic_id else tactic_name,
                "technique": f"{tech_name} ({sub_id or tech_id})" if (tech_id or sub_id) else tech_name
            })

    rule_name = (
        src.get("kibana.alert.rule.name")
        or src.get("message")
        or src.get("rule", {}).get("name")
    )
    severity = src.get("kibana.alert.severity") or src.get("event", {}).get("severity")
    risk = src.get("kibana.alert.risk_score") or src.get("event", {}).get("risk_score")
    event_code = (
        src.get("event", {}).get("code")
        or src.get("kibana.alert.original_event", {}).get("code")
    )

    return {
        "timestamp": src.get("@timestamp"),
        "rule_name": rule_name,
        "severity": severity,
        "risk_score": risk,
        "event_code": event_code,
        "process_name": proc.get("name"),
        "process_pid": proc.get("pid"),
        "api_name": api_info.get("name"),
        "api_summary": api_info.get("summary"),
        "api_behaviors": api_info.get("behaviors", []),
        "api_parameters": api_info.get("parameters", {}),
        "memory_region_protection": mem_info.get("region_protection"),
        "call_stack_summary": thread_ext.get("call_stack_summary"),
        "mitre_attack": mitre_list,
        "reason": src.get("kibana.alert.reason") or src.get("message")
    }


def query_wazuh_alerts_once(process_name, time_from, time_to, sha256_hash=None):
    should_clauses = [
        {"wildcard": {"data.win.eventdata.image": f"*{process_name}*"}},
        {"wildcard": {"data.win.eventdata.targetFilename": f"*{process_name}*"}},
        {"wildcard": {"data.win.eventdata.parentImage": f"*{process_name}*"}},
        {"wildcard": {"data.win.eventdata.newProcessName": f"*{process_name}*"}},
        {"wildcard": {"data.win.eventdata.parentProcessName": f"*{process_name}*"}},
        {"match_phrase": {"full_log": process_name}}
    ]

    if sha256_hash and sha256_hash != "N/A":
        should_clauses.append({"wildcard": {"data.win.eventdata.hashes": f"*{sha256_hash.upper()}*"}})
        should_clauses.append({"wildcard": {"data.win.eventdata.hashes": f"*{sha256_hash.lower()}*"}})

    must_clauses = [
        {"term": {"agent.id": WAZUH_AGENT_ID}},
        {
            "bool": {
                "should": should_clauses,
                "minimum_should_match": 1
            }
        }
    ]

    query = {
        "query": {
            "bool": {
                "must": must_clauses,
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": time_from,
                                "lte": time_to
                            }
                        }
                    }
                ]
            }
        },
        "sort": [{"@timestamp": "asc"}],
        "size": 100
    }

    try:
        resp = requests.post(
            f"{WAZUH_INDEXER_URL}/{WAZUH_ALERT_INDEX}/_search",
            auth=WAZUH_AUTH,
            verify=False,
            json=query,
            timeout=10
        )
        if resp.status_code == 200:
            hits = resp.json().get("hits", {}).get("hits", [])
            return [h["_source"] for h in hits]
        else:
            print(f"[-] Wazuh Indexer returned HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        print(f"[-] Wazuh Indexer query error: {e}")
    return []


def parse_wazuh_alert(src):
    rule = src.get("rule", {})
    mitre = rule.get("mitre", {})
    data_win = src.get("data", {}).get("win", {})
    event_data = data_win.get("eventdata", {})
    sys_info = data_win.get("system", {})

    mitre_list = []
    t_ids = mitre.get("id", [])
    tactics = mitre.get("tactic", [])
    techniques = mitre.get("technique", [])

    max_len = max(len(t_ids), len(techniques), 1) if (t_ids or techniques) else 0
    for idx in range(max_len):
        tid = t_ids[idx] if idx < len(t_ids) else (t_ids[0] if t_ids else "N/A")
        tech = techniques[idx] if idx < len(techniques) else (techniques[0] if techniques else "Unknown")
        tac = tactics[idx] if idx < len(tactics) else (", ".join(tactics) if tactics else "Unknown")
        mitre_list.append({
            "id": tid,
            "tactic": tac,
            "technique": tech
        })

    level = rule.get("level", 0)
    groups = rule.get("groups", [])
    desc = rule.get("description", "")

    HIGH_RISK_TACTICS = {
        "execution", "defense evasion", "privilege escalation",
        "persistence", "credential access", "lateral movement", "impact"
    }
    has_high_risk_mitre = any(
        any(hrt in str(m.get("tactic", "")).lower() for hrt in HIGH_RISK_TACTICS)
        for m in mitre_list
    )

    SUSPICIOUS_GROUPS = {
        "malware", "rootcheck", "sysmon_process-anomalies",
        "sysmon_eid8_detections", "sysmon_eid10_detections"
    }

    rule_id_str = str(rule.get("id"))
    is_suspicious = (
        level >= 7
        or (level >= 4 and has_high_risk_mitre)
        or rule_id_str in ["92052"]
        or any(g in SUSPICIOUS_GROUPS for g in groups)
    )

    return {
        "timestamp": src.get("@timestamp"),
        "rule_id": rule.get("id"),
        "rule_level": level,
        "rule_description": desc,
        "rule_groups": groups,
        "is_suspicious": is_suspicious,
        "mitre_attack": mitre_list,
        "event_id": sys_info.get("eventID"),
        "channel": sys_info.get("channel"),
        "image": event_data.get("image") or event_data.get("newProcessName"),
        "command_line": event_data.get("commandLine"),
        "parent_image": event_data.get("parentImage") or event_data.get("parentProcessName"),
        "target_filename": event_data.get("targetFilename"),
        "hashes": event_data.get("hashes")
    }


def background_poll_elastic(sha256, filename, exec_start, exec_end, target_engine="both"):
    """Poll Elasticsearch & Wazuh Indexer in parallel for alerts related to the executed process."""
    if exec_start:
        try:
            st = datetime.fromisoformat(exec_start.replace("Z", "+00:00"))
            time_from = (st - timedelta(seconds=30)).isoformat()
        except Exception:
            time_from = "now-5m"
    else:
        time_from = "now-5m"

    if exec_end:
        try:
            et = datetime.fromisoformat(exec_end.replace("Z", "+00:00"))
            time_to = (et + timedelta(seconds=90)).isoformat()
        except Exception:
            time_to = "now"
    else:
        time_to = "now"

    print(f"\n[*] [EDR Worker] Polling alerts for {filename} ({sha256[:8]}) [Target: {target_engine}]...")
    all_es_hits = []
    seen_es_ids = set()

    all_wz_hits = []
    seen_wz_keys = set()

    for attempt in range(1, MAX_POLL_ATTEMPTS + 1):
        time.sleep(POLL_INTERVAL_SECONDS)

        # 1. Query Elastic
        if target_engine in ("elastic", "both"):
            raw_es = query_elastic_alerts_once(
                process_name=filename,
                time_from=time_from,
                time_to=time_to,
                sha256_hash=sha256
            )
            for h in raw_es:
                doc_id = (
                    h.get("event", {}).get("id")
                    or h.get("kibana.alert.uuid")
                    or str(h.get("@timestamp")) + str(h.get("message"))
                )
                if doc_id not in seen_es_ids:
                    seen_es_ids.add(doc_id)
                    all_es_hits.append(h)

        # 2. Query Wazuh
        if target_engine in ("wazuh", "both"):
            raw_wz = query_wazuh_alerts_once(
                process_name=filename,
                time_from=time_from,
                time_to=time_to,
                sha256_hash=sha256
            )
            for h in raw_wz:
                key = (h.get("@timestamp"), h.get("rule", {}).get("id"), h.get("id"))
                if key not in seen_wz_keys:
                    seen_wz_keys.add(key)
                    all_wz_hits.append(h)

        es_behavior = [
            h for h in all_es_hits
            if (h.get("event", {}).get("code") == "behavior"
                or h.get("kibana.alert.original_event", {}).get("code") == "behavior")
        ]
        parsed_wz_temp = [parse_wazuh_alert(h) for h in all_wz_hits]
        wz_suspicious = [a for a in parsed_wz_temp if a["is_suspicious"]]

        if ((es_behavior if target_engine == "elastic" else False) or
            (wz_suspicious if target_engine == "wazuh" else False) or
            ((es_behavior or wz_suspicious) if target_engine == "both" else False)) and attempt >= 2:
            print(f"[+] [EDR Worker] Early stop at poll #{attempt} (ES: {len(es_behavior)}, Wazuh: {len(wz_suspicious)})")
            break

    # Parse Elastic results
    if target_engine in ("elastic", "both"):
        parsed_es = [parse_elastic_alert(h) for h in all_es_hits]
        behavior_alerts_es = [a for a in parsed_es if a.get("event_code") == "behavior"]
        file_alerts_es = [a for a in parsed_es if a.get("event_code") == "malicious_file"]
        elastic_result = {
            "behavior_detected": len(behavior_alerts_es) > 0,
            "behavior_alert_count": len(behavior_alerts_es),
            "file_detected": len(file_alerts_es) > 0,
            "file_alert_count": len(file_alerts_es),
            "alerts": parsed_es
        }

    # Parse Wazuh results
    if target_engine in ("wazuh", "both"):
        parsed_wz = [parse_wazuh_alert(h) for h in all_wz_hits]
        suspicious_wz = [a for a in parsed_wz if a["is_suspicious"]]
        wazuh_result = {
            "detected": len(suspicious_wz) > 0,
            "suspicious_alert_count": len(suspicious_wz),
            "total_alert_count": len(parsed_wz),
            "suspicious_alerts": suspicious_wz,
            "all_alerts": parsed_wz
        }

    with SESSIONS_LOCK:
        if sha256 in SESSIONS:
            if target_engine in ("elastic", "both"):
                SESSIONS[sha256]["elastic_defend"] = elastic_result
            if target_engine in ("wazuh", "both"):
                SESSIONS[sha256]["wazuh_defend"] = wazuh_result
            if target_engine == "elastic":
                SESSIONS[sha256]["status"] = "COMPLETED_ELASTIC"
            elif target_engine == "wazuh":
                SESSIONS[sha256]["status"] = "COMPLETED_WAZUH"
            else:
                SESSIONS[sha256]["status"] = "COMPLETED"

    # Save dedicated reports for standalone evaluations
    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    if target_engine in ("elastic", "both"):
        rep_elastic = {
            "filename": filename,
            "sha256": sha256,
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
            "elastic_defend": elastic_result,
            "execution_telemetry": SESSIONS.get(sha256, {}).get("execution_telemetry", {})
        }
        out_e = os.path.join(ELASTIC_OUTPUT_DIR, f"{filename}_{ts_str}.json")
        try:
            with open(out_e, "w", encoding="utf-8") as f:
                json.dump(rep_elastic, f, indent=4)
            print(f"[+] Saved Elastic Defend report to: {out_e}")
        except Exception as e:
            print(f"[-] Error writing elastic report: {e}")

    if target_engine in ("wazuh", "both"):
        rep_wazuh = {
            "filename": filename,
            "sha256": sha256,
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
            "wazuh_defend": wazuh_result,
            "execution_telemetry": SESSIONS.get(sha256, {}).get("execution_telemetry", {})
        }
        out_w = os.path.join(WAZUH_OUTPUT_DIR, f"{filename}_{ts_str}.json")
        try:
            with open(out_w, "w", encoding="utf-8") as f:
                json.dump(rep_wazuh, f, indent=4)
            print(f"[+] Saved Wazuh report to: {out_w}")
        except Exception as e:
            print(f"[-] Error writing wazuh report: {e}")

    print(f"[+] [EDR Worker] Completed for {filename} ({sha256[:8]}) [Target: {target_engine}]")


@app.route("/api/v1/status", methods=["GET"])
def healthcheck():
    return jsonify({
        "status": "healthy",
        "service": "unified_listener_server",
        "port": PORT,
        "active_sessions": len(SESSIONS)
    }), 200


@app.route("/report", methods=["POST"])
@app.route("/defender_static", methods=["POST"])
@app.route("/api/v1/defender_static", methods=["POST"])
def receive_defender_static():
    """Endpoint for Windows Agent Static Defender scan results."""
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No JSON payload"}), 400

    filename = data.get("filename", "unknown")
    shared_path = os.path.join(SHARED_DIR, filename)
    md5_val, sha256_val, file_size = calc_file_hashes(shared_path)

    # Use hash sent by agent if Linux file missing
    if sha256_val == "N/A" and data.get("sha256"):
        sha256_val = data.get("sha256")
        md5_val = data.get("md5", "N/A")
        file_size = data.get("file_size_bytes", 0)

    session = get_or_create_session(sha256_val, filename=filename, md5=md5_val, size_bytes=file_size)

    events = data.get("events", [])
    detected = data.get("defender_detected", False) or len(events) > 0

    session["defender_static"] = {
        "detected": detected,
        "status": data.get("status", "UNKNOWN"),
        "events": events,
        "system_info": data.get("defender_system_info", {})
    }
    if detected:
        session["windows_defender"] = {
            "detected": True,
            "stage": "STATIC",
            "status": data.get("status", "QUARANTINED"),
            "threat_name": events[0].get("ThreatName") if events else None,
            "events": events,
            "system_info": data.get("defender_system_info", {})
        }
        if CURRENT_PHASE == "binhthuong":
            session["status"] = "COMPLETED_BINHTHUONG"

    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_s = os.path.join(STATIC_OUTPUT_DIR, f"{filename}_{ts_str}.json")
    try:
        with open(out_s, "w", encoding="utf-8") as f:
            json.dump({
                "filename": filename,
                "sha256": sha256_val,
                "md5": md5_val,
                "file_size_bytes": file_size,
                "evaluated_at": datetime.now(timezone.utc).isoformat(),
                "defender_static": session["defender_static"],
                "windows_defender": session.get("windows_defender", {})
            }, f, indent=4)
        print(f"[+] Saved Defender Static report to: {out_s}")
    except Exception as e:
        print(f"[-] Error writing static report: {e}")

    print(f"\n[+] [API] /defender_static: {filename} ({sha256_val[:8]}) -> Detected: {detected}")
    return jsonify({"status": "accepted", "sha256": sha256_val, "detected": detected}), 200


@app.route("/behavior_report", methods=["POST"])
@app.route("/api/v1/behavior_report", methods=["POST"])
def receive_behavior_report():
    """Endpoint for Windows Agent Dynamic Behavior & Telemetry."""
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No JSON payload"}), 400

    filename = data.get("filename", "unknown")
    shared_path = os.path.join(SHARED_DIR, filename)
    md5_val, sha256_val, file_size = calc_file_hashes(shared_path)

    if sha256_val == "N/A" and data.get("sha256"):
        sha256_val = data.get("sha256")
        md5_val = data.get("md5", "N/A")
        file_size = data.get("file_size_bytes", 0)

    session = get_or_create_session(sha256_val, filename=filename, md5=md5_val, size_bytes=file_size)

    # 1. Unified Windows Defender (Static wait or Runtime behavior)
    win_def = data.get("windows_defender")
    if not win_def:
        def_events = data.get("defender_events", [])
        beh_det = data.get("defender_behavior_detected", False) or len(def_events) > 0
        win_def = {
            "detected": beh_det,
            "stage": "BEHAVIOR" if beh_det else "NONE",
            "status": "DETECTED_BEHAVIOR" if beh_det else "CLEAN",
            "threat_name": def_events[0].get("ThreatName") if def_events else None,
            "events": def_events,
            "system_info": data.get("defender_system_info", {})
        }

    session["windows_defender"] = win_def
    # Legacy keys for backwards compatibility
    session["defender_static"] = {"detected": win_def.get("stage") == "STATIC", "status": win_def.get("status")}
    session["defender_behavior"] = {"detected": win_def.get("stage") == "BEHAVIOR", "alert_count": len(win_def.get("events", []))}

    # 2. Execution Telemetry
    session["execution_telemetry"] = {
        "execution_status": data.get("execution_status", "UNKNOWN"),
        "main_pid": data.get("main_pid"),
        "exec_start_iso": data.get("exec_start_iso"),
        "exec_end_iso": data.get("exec_end_iso"),
        "child_processes": data.get("child_processes", []),
        "network_connections": data.get("network_connections", []),
        "decoy_file_modifications": data.get("decoy_file_modifications", {})
    }

    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_b = os.path.join(BEHAVIOR_OUTPUT_DIR, f"{filename}_{ts_str}.json")
    try:
        with open(out_b, "w", encoding="utf-8") as f:
            json.dump({
                "filename": filename,
                "sha256": sha256_val,
                "md5": md5_val,
                "file_size_bytes": file_size,
                "evaluated_at": datetime.now(timezone.utc).isoformat(),
                "windows_defender": session["windows_defender"],
                "execution_telemetry": session["execution_telemetry"]
            }, f, indent=4)
        print(f"[+] Saved Defender Behavior report to: {out_b}")
    except Exception as e:
        print(f"[-] Error writing behavior report: {e}")

    # Phase-specific routing
    if CURRENT_PHASE in ("binhthuong", "all"):
        session["status"] = "COMPLETED_BINHTHUONG" if CURRENT_PHASE == "binhthuong" else "COMPLETED"
        print(f"\n[+] [API] /behavior_report: Phase '{CURRENT_PHASE}' finished for {filename} ({sha256_val[:8]}). Defender: {win_def.get('status')}")
        return jsonify({"status": "accepted", "sha256": sha256_val, "message": "Phase completed."}), 200

    elif CURRENT_PHASE == "elastic":
        session["status"] = "POLLING_ELASTIC"
        print(f"\n[+] [API] /behavior_report: Phase 'elastic' telemetry received, polling Elasticsearch...")
        t = threading.Thread(
            target=background_poll_elastic,
            args=(sha256_val, filename, data.get("exec_start_iso"), data.get("exec_end_iso"), "elastic"),
            daemon=True
        )
        t.start()
        return jsonify({"status": "accepted", "sha256": sha256_val, "message": "Telemetry received, polling Elastic."}), 200

    elif CURRENT_PHASE == "wazuh":
        session["status"] = "POLLING_WAZUH"
        print(f"\n[+] [API] /behavior_report: Phase 'wazuh' telemetry received, polling Wazuh Indexer...")
        t = threading.Thread(
            target=background_poll_elastic,
            args=(sha256_val, filename, data.get("exec_start_iso"), data.get("exec_end_iso"), "wazuh"),
            daemon=True
        )
        t.start()
        return jsonify({"status": "accepted", "sha256": sha256_val, "message": "Telemetry received, polling Wazuh."}), 200

    # If quarantined in Stage 1 (Static wait), no dynamic execution occurred
    if win_def.get("stage") == "STATIC":
        session["elastic_defend"] = {"behavior_detected": False, "behavior_alert_count": 0, "file_detected": False, "file_alert_count": 0, "alerts": []}
        session["wazuh_defend"] = {"detected": False, "suspicious_alert_count": 0, "total_alert_count": 0, "suspicious_alerts": [], "all_alerts": []}
        session["status"] = "COMPLETED"
        print(f"\n[+] [API] /behavior_report: {filename} ({sha256_val[:8]}) -> Windows Defender QUARANTINED in Static Stage. Session completed.")
        return jsonify({"status": "accepted", "sha256": sha256_val, "message": "Quarantined statically by Defender, completed."}), 200

    session["status"] = "POLLING_EDRS"
    print(f"\n[+] [API] /behavior_report: {filename} ({sha256_val[:8]}) -> Windows Defender: {win_def.get('detected')} (Stage: {win_def.get('stage')})")

    # 3. Spawn background thread for Elastic & Wazuh polling
    t = threading.Thread(
        target=background_poll_elastic,
        args=(sha256_val, filename, data.get("exec_start_iso"), data.get("exec_end_iso"), "both"),
        daemon=True
    )
    t.start()

    return jsonify({
        "status": "accepted",
        "sha256": sha256_val,
        "message": "Telemetry received, polling Elastic & Wazuh in background."
    }), 200


@app.route("/elastic_behavior_report", methods=["POST"])
def receive_elastic_behavior_report():
    """Endpoint for standalone elastic_behavior_agent.py (Port 8002)."""
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No JSON payload"}), 400

    filename = data.get("filename", "unknown")
    shared_path = os.path.join(SHARED_DIR, filename)
    md5_val, sha256_val, file_size = calc_file_hashes(shared_path)

    if sha256_val == "N/A" and data.get("sha256"):
        sha256_val = data.get("sha256")
        md5_val = data.get("md5", "N/A")
        file_size = data.get("file_size_bytes", 0)

    session = get_or_create_session(sha256_val, filename=filename, md5=md5_val, size_bytes=file_size)
    session["execution_telemetry"] = {
        "execution_status": data.get("execution_status", "UNKNOWN"),
        "main_pid": data.get("main_pid"),
        "exec_start_iso": data.get("exec_start_iso"),
        "exec_end_iso": data.get("exec_end_iso"),
        "child_processes": data.get("child_processes", []),
        "network_connections": data.get("network_connections", []),
        "decoy_file_modifications": data.get("decoy_file_modifications", {})
    }
    session["status"] = "POLLING_ELASTIC"
    print(f"\n[+] [API] /elastic_behavior_report: {filename} ({sha256_val[:8]}) -> Polling Elasticsearch (port 9201)...")

    t = threading.Thread(
        target=background_poll_elastic,
        args=(sha256_val, filename, data.get("exec_start_iso"), data.get("exec_end_iso"), "elastic"),
        daemon=True
    )
    t.start()
    return jsonify({
        "status": "accepted",
        "sha256": sha256_val,
        "message": "Telemetry received, polling Elastic in background."
    }), 200


@app.route("/wazuh_behavior_report", methods=["POST"])
def receive_wazuh_behavior_report():
    """Endpoint for standalone wazuh_behavior_agent.py (Port 8002)."""
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No JSON payload"}), 400

    filename = data.get("filename", "unknown")
    shared_path = os.path.join(SHARED_DIR, filename)
    md5_val, sha256_val, file_size = calc_file_hashes(shared_path)

    if sha256_val == "N/A" and data.get("sha256"):
        sha256_val = data.get("sha256")
        md5_val = data.get("md5", "N/A")
        file_size = data.get("file_size_bytes", 0)

    session = get_or_create_session(sha256_val, filename=filename, md5=md5_val, size_bytes=file_size)
    session["execution_telemetry"] = {
        "execution_status": data.get("execution_status", "UNKNOWN"),
        "main_pid": data.get("main_pid"),
        "exec_start_iso": data.get("exec_start_iso"),
        "exec_end_iso": data.get("exec_end_iso"),
        "child_processes": data.get("child_processes", []),
        "network_connections": data.get("network_connections", []),
        "decoy_file_modifications": data.get("decoy_file_modifications", {})
    }
    session["status"] = "POLLING_WAZUH"
    print(f"\n[+] [API] /wazuh_behavior_report: {filename} ({sha256_val[:8]}) -> Polling Wazuh Indexer (port 9200)...")

    t = threading.Thread(
        target=background_poll_elastic,
        args=(sha256_val, filename, data.get("exec_start_iso"), data.get("exec_end_iso"), "wazuh"),
        daemon=True
    )
    t.start()
    return jsonify({
        "status": "accepted",
        "sha256": sha256_val,
        "message": "Telemetry received, polling Wazuh in background."
    }), 200


@app.route("/api/v1/session/<sha256>", methods=["GET"])
def query_session(sha256):
    with SESSIONS_LOCK:
        if sha256 not in SESSIONS:
            return jsonify({"status": "not_found"}), 404
        return jsonify(SESSIONS[sha256]), 200


@app.route("/api/v1/phase", methods=["POST"])
def set_pipeline_phase():
    global CURRENT_PHASE
    data = request.get_json() or {}
    new_phase = data.get("phase", "all")
    sha256 = data.get("sha256")
    CURRENT_PHASE = new_phase
    with SESSIONS_LOCK:
        if sha256 and sha256 in SESSIONS:
            SESSIONS[sha256]["status"] = f"AWAITING_{new_phase.upper()}"
    print(f"\n[*] [API] Pipeline Phase set to: '{CURRENT_PHASE}' (sha256: {sha256[:8] if sha256 else 'N/A'})")
    return jsonify({"status": "ok", "current_phase": CURRENT_PHASE}), 200


if __name__ == "__main__":
    print(f"[*] Starting Unified Detection Server on port {PORT}...")
    print(f"[*] Shared Directory  : {SHARED_DIR}")
    print(f"[*] Elasticsearch     : {ES_URL}")
    print(f"[*] Wazuh Indexer     : {WAZUH_INDEXER_URL}")
    print(f"[*] Endpoints active  : /report, /behavior_report, /elastic_behavior_report, /wazuh_behavior_report, /api/v1/*")
    app.run(host="0.0.0.0", port=PORT)
