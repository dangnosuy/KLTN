# Behavior Verifier (Đóng góp C1)

> **Thesis**: *Adaptive Program Transformation for Robustness Evaluation of Malware Detection Systems*  
> **Module**: Three-State Outcome-Based Behavior Verifier (`BUILD_FAIL`, `UNDETERMINED`, `PASSED_TEST`)

---

## 1. Mục tiêu & Nguyên lý Thiết kế

Trong bài toán biến đổi mã nguồn C né tránh phát hiện (Problem-Space Evasion), việc biến đổi cú pháp rất dễ tạo ra các biến thể lỗi (không biên dịch được, hoặc biên dịch được nhưng crash bộ nhớ `0xC0000005`, infinite loop, unhandled SEH). Khi đưa các biến thể lỗi này đi truy vấn Detector, nhiều detector tĩnh hoặc động sẽ không gắn cờ cảnh báo, dẫn đến nguy cơ **đánh giá nhầm biến thể hỏng là đã né tránh thành công (False Positive Evasion)**, làm thổi phồng tỷ lệ bypass thực nghiệm.

Để giải quyết bài toán này, **Behavior Verifier (C1)** thiết lập cơ chế kiểm chứng 3 trạng thái:
1. **`BUILD_FAIL`**: Lỗi cú pháp biên dịch (syntax error, undeclared symbol, invalid compiler flag).
2. **`UNDETERMINED`**: Biên dịch thành công nhưng thất bại ở pha thực thi (Runtime Crash, Access Violation `0xC0000005`, Timeout watchdog, hoặc sai/thiếu Canary Proof Marker).
3. **`PASSED_TEST`**: Biên dịch thành công **VÀ** vượt qua 100% hợp đồng kiểm chứng chức năng (Exit code 0 + Khớp đúng Proof Marker `c1_proof.txt`).

Verifier kiểm chứng dựa trên **Outcome-based Execution Protocol** (tương tự triết lý của TransForge), chạy trong sandbox cô lập tạm thời, hoàn tất toàn bộ chu trình kiểm tra chỉ trong **~25–35ms/mẫu**, đủ nhanh để nhúng trực tiếp vào vòng lặp tìm kiếm tiến hóa (NSGA-II) và điều phối LLM Agent (C2).

---

## 2. Cấu trúc Thư mục

```text
sources/
├── dataset/
│   ├── manifest.json                  # Bảng kê 35 mẫu thử nghiệm (7 nhóm x 5)
│   ├── common/
│   │   ├── c1_proof.h                 # Macro & hàm ghi deterministic canary proof
│   │   └── c1_mock_listener.h         # Fallback socket listener cho kiểm thử C2 nội bộ
│   ├── g1_*.c & .json                 # Process Injection
│   ├── g2_*.c & .json                 # Execution Hijacking
│   ├── g3_*.c & .json                 # API & Hook Evasion
│   ├── g4_*.c & .json                 # Anti-Analysis & Memory Evasion (Alternative Behavior)
│   ├── g5_*.c & .json                 # Recon & In-Memory Scraping
│   ├── g6_*.c & .json                 # C2 Network & Exfiltration
│   └── g7_*.c & .json                 # Benign System Controls (FP baseline)
└── verifier/
    ├── verifier.ps1                   # Native PowerShell Verifier (hỗ trợ MSVC/MinGW)
    ├── verifier.py                    # Python Verifier Engine (dùng cho Linux/Pipeline)
    ├── test_verifier.ps1              # Bộ tự kiểm thử (Self-test) kiểm chứng 3 trạng thái
    └── README.md                      # Tài liệu hướng dẫn này
```

---

## 3. Cách Sử dụng

### 3.1. Chạy trên Windows (PowerShell)

#### Kiểm tra toàn bộ 35 mẫu trong dataset:
```powershell
powershell -ExecutionPolicy Bypass -File sources\verifier\verifier.ps1 -All
```

#### Kiểm tra một nhóm kỹ thuật cụ thể:
```powershell
powershell -ExecutionPolicy Bypass -File sources\verifier\verifier.ps1 -Group group_1_process_injection
powershell -ExecutionPolicy Bypass -File sources\verifier\verifier.ps1 -Group group_4_anti_analysis_memory_evasion
powershell -ExecutionPolicy Bypass -File sources\verifier\verifier.ps1 -Group group_6_c2_network_exfiltration
```

#### Kiểm tra một mẫu hoặc biến thể đơn lẻ:
```powershell
powershell -ExecutionPolicy Bypass -File sources\verifier\verifier.ps1 -SampleId g1_01_local_thread
```

#### Xuất kết quả dạng JSON:
```powershell
powershell -ExecutionPolicy Bypass -File sources\verifier\verifier.ps1 -All -JsonOutput
```

#### Chạy bộ tự kiểm chứng (Self-test) phân loại 3 trạng thái:
```powershell
powershell -ExecutionPolicy Bypass -File sources\verifier\test_verifier.ps1
```

### 3.2. Chạy trên Linux / Cross-Platform (Python)

```bash
# Kiểm tra 1 mẫu
python sources/verifier/verifier.py --sample g1_01_local_thread

# Kiểm tra toàn bộ
python sources/verifier/verifier.py --all

# Chọn trình biên dịch cụ thể (auto, msvc, gcc, clang)
python sources/verifier/verifier.py --all --compiler gcc
```

---

## 4. Đặc tả Hợp đồng Kiểm chứng (`.json`)

Mỗi file mã nguồn C trong dataset được gắn kèm một file JSON định nghĩa hợp đồng kiểm chứng:

```json
{
  "id": "g4_01_antidebug_peb",
  "name": "PEB BeingDebugged Anti-Analysis with Alternative Behavior",
  "group": "group_4_anti_analysis_memory_evasion",
  "tactic": "TA0005_Defense_Evasion",
  "technique": "T1497.001",
  "build": {
    "sources": ["g4_01_antidebug_peb.c"],
    "include_dirs": ["."],
    "flags": ["-O2", "-Wall"],
    "libraries": ["kernel32"]
  },
  "execution": {
    "timeout_seconds": 15,
    "arguments": [],
    "expected_exit_code": 0
  },
  "verification": {
    "proof_type": "file_marker",
    "proof_file": "c1_proof.txt",
    "expected_marker": "[C1_PROOF] ID: g4_01_antidebug_peb | STATUS: SUCCESS",
    "alternative_marker": "[C1_PROOF] ID: g4_01_antidebug_peb | STATUS: ALTERNATIVE_DEBUGGER_DETECTED",
    "sysmon_events": [1]
  }
}
```

- **Alternative Marker (Nhóm 4)**: Cho phép mẫu Anti-Analysis kích hoạt nhánh hành vi thay thế hợp lệ mà không bị đánh rớt thành `UNDETERMINED`.
- **Sandbox Isolation**: Mỗi lần chạy kiểm chứng, Verifier tạo thư mục tạm `sources/verifier/build/sandbox_<id>/` để biên dịch, thực thi và kiểm tra marker, sau đó tự động dọn dẹp sạch sẽ.
