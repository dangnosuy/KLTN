# Unified Multi-Layer Malware Detection Pipeline

> Cụm detector chính hiện tại: **EMBER, MalConv, ClamAV, Defender CLI offline
> (chỉ static) và CAPE behavior (ngưỡng 4)**. Chạy bằng
> `python3 -m pipeline.detectors`; xem [hướng dẫn mới](detectors/README.md).
> Các phần bên dưới mô tả pipeline cũ, được giữ lại để tương thích/tham khảo.

Hệ thống đánh giá tự động đa tầng (Multi-Layer Detection Pipeline) kết hợp 3 lớp phòng thủ và 8 detector engines:
- **Layer 1: Signature-Based**: ClamAV, YARA rules.
- **Layer 2: ML-Based**: SOREL-20M (PyTorch DNN), EMBER 2024 (LightGBM PE Tree), MalConv (Raw Byte CNN).
- **Layer 3: Dynamic EDR**: Elastic Defend EDR, Wazuh EDR (Sysmon).
- **Windows Defender Suite**: Host AV/EDR nguyên khối (Stage 1: Treo đĩa 10s quét tĩnh on-access -> Stage 2: Kích nổ sandbox 20s quét hành vi runtime).

---

## Kiến trúc hệ thống

```
                          [ python3 pipeline/run_pipeline.py <file_or_dir> ]
                                                  │
         ┌────────────────────────────────────────┴────────────────────────────────────────┐
         ▼                                                                                 ▼
  [ Phase 1 & 2: Local Linux Engines ]                                    [ Phase 3: Windows VM Evaluation ]
    ├─ ClamAV (clamscan)                                                    ├─ Copy file -> shared_payloads/
    ├─ YARA (yara_scan_all.py)                                              │
    ├─ SOREL-20M (Sophos PyTorch)                                           ▼
    ├─ EMBER 2024 (LightGBM PE Tree)                              [ unified_win_agent.py trên Windows VM ]
    └─ MalConv (Raw-Byte CNN)                                       ├─ Stage 1: Treo đĩa 10s (chờ Defender On-Access Static)
                                                                    │    └─ Quarantined? Báo cáo ngay & Dừng.
                                                                    └─ Stage 2: Kích nổ Sandbox C:\Elastic_Testing (20s)
                                                                         ├─ Rải 4 decoy files, monitor child procs, net conns
                                                                         ├─ Bắt Defender Runtime Behavior (Event 1116/1117)
                                                                         └─ POST /api/v1/behavior_report
                                                                    ▼
                                                        [ unified_server.py trên Linux (Port 8002) ]
                                                          ├─ Tiếp nhận Windows Defender & telemetry logs
                                                          ├─ Background Worker: Polling song song:
                                                          │    ├─ Elasticsearch (Port 9201, Elastic Defend)
                                                          │    └─ Wazuh OpenSearch (Port 9200, Sysmon/Wazuh)
                                                          └─ Cập nhật session cache theo SHA256
                                                                    │
         ┌──────────────────────────────────────────────────────────┘
         ▼
  [ Pipeline Correlator ]
    └─ Gộp toàn bộ kết quả thành 1 file JSON chuẩn hóa:
       pipeline/reports/<filename>_<sha256[:8]>.json
```

---

## Hướng dẫn vận hành

### 1. Khởi động Listener Server (Linux Host)
Chạy server hợp nhất trên port `8002`:
```bash
python3 pipeline/unified_server.py
```

### 2. Khởi động Agent trên Windows Guest VM
Copy file `pipeline/unified_win_agent.py` sang máy Windows VM và chạy với quyền **Administrator**:
```powershell
python unified_win_agent.py
```

### 3. Chạy Pipeline đánh giá mẫu thử (Linux Host)

- **Đánh giá 1 mẫu thử đầy đủ (cả 3 layers: Static + ML + VM Behavior)**:
  ```bash
  python3 pipeline/run_pipeline.py dataset/advanced/build/crt_inject.exe
  ```

- **Đánh giá 1 thư mục chứa nhiều file `.exe` tuần tự tự động**:
  ```bash
  python3 pipeline/run_pipeline.py dataset/advanced/build/
  ```

- **Chỉ chạy Layer 1 & 2 cục bộ trên Linux (bỏ qua Windows VM)**:
  ```bash
  python3 pipeline/run_pipeline.py dataset/advanced/build/crt_inject.exe --skip-behavior
  ```

### 4. Kết quả đầu ra
Mỗi mẫu thử tạo ra một file JSON duy nhất tại `pipeline/reports/<filename>_<sha256[:8]>.json`:
- `metadata`: Tên file, SHA256, MD5, dung lượng, thời điểm quét.
- `layer1_signature`: ClamAV, YARA.
- `layer2_machine_learning`: SOREL-20M score & tags, EMBER 2024 score, MalConv raw prediction.
- `layer3_behavior`: Telemetry thực thi, Elastic Defend EDR alerts, Wazuh EDR (Sysmon) alerts.
- `windows_defender`: Báo cáo hợp nhất (detected, stage: STATIC/BEHAVIOR/NONE, status, threat_name, events).
- `summary`: Tỉ lệ bypass, tổng số engine phát hiện / né tránh (trên 8 engines), và verdict tổng thể (`FULLY_EVADED`, `HIGHLY_EVASIVE`, `PARTIALLY_EVADED`, `BLOCKED`).

---

## Direct VMRun Pipeline

`vmrun_pipeline.py` là pipeline dynamic mới, không dùng SMB share hoặc Windows Python watcher. Nó chạy theo engine-major và revert từng sample về golden snapshot: `elastic`, `wazuh`, `normal_real`. Snapshot `normal_real` bắt buộc Windows Defender; Sysmon được thu thập nếu có nhưng không bắt buộc.

Hướng dẫn vận hành đầy đủ, bao gồm môi trường, input/output, tham số CLI, kết quả và xử lý lỗi: [VMRUN_PIPELINE_OPERATION_GUIDE.md](VMRUN_PIPELINE_OPERATION_GUIDE.md).

Tạo file environment riêng từ `pipeline/vmrun.env.example`, điền credential và không commit file đó. Sau đó chạy kiểm tra hạ tầng trước; lệnh này sẽ lần lượt revert các snapshot để kiểm tra VMware Tools, guest services, clock skew và backend health:

```bash
set -a; source /path/to/vmrun.env; set +a
python3 pipeline/vmrun_pipeline.py doctor --campaign thesis-r01
```

Doctor cũng từ chối snapshot `elastic`/`wazuh` nếu Windows Defender còn bật, vì alert hoặc quarantine của Defender sẽ làm sai attribution. Với Wazuh, `ossec.conf` phải subscribe channel `Microsoft-Windows-Sysmon/Operational`. CLI trả exit code khác 0 nếu bất kỳ readiness gate hoặc job nào lỗi, sau khi đã lưu report để điều tra.

Sysmon Event ID 8 mặc định chỉ tạo Wazuh alert mức 0 cho nhiều target. Để benchmark process injection vào Notepad có alert truy vấn được, cài rule `100203` trên Wazuh manager rồi kiểm tra cấu hình trước khi restart:

```bash
sudo install -o wazuh -g wazuh -m 660 \
  Wazuh-Defend/rules/100203_process_injection.xml \
  /var/ossec/etc/rules/100203_process_injection.xml
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
```

Không cài file riêng nếu rule ID `100203` đã được merge vào `/var/ossec/etc/rules/local_rules.xml`, vì Wazuh không chấp nhận trùng rule ID.

Chạy batch dynamic với thứ tự cố định có thể tái lập:

```bash
python3 pipeline/vmrun_pipeline.py run dataset/advanced/build \
  --campaign thesis-r01 \
  --engines elastic,wazuh,defender \
  --shuffle-seed 23520146
```

Kết quả, raw Defender evidence và `state.json` được lưu tại `pipeline/vmrun_reports/<campaign>/`. Chạy lại cùng campaign sẽ bỏ qua duy nhất các `(engine, SHA256)` đã `COMPLETED`; job lỗi sẽ revert và thử lại ở lần sau.
