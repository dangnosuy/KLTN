# Adaptive Program Transformation & Robustness Evaluation Pipeline

> **Khóa luận Tốt nghiệp / Nghiên cứu Khoa học**: *Adaptive Program Transformation for Robustness Evaluation of Malware Detection Systems*  
> **Cụm Động cơ Đánh giá chính**: **ClamAV, EMBER, MalConv, Windows Defender CLI, và CAPE Sandbox 2.5**.  
> **Đóng góp chính (Contributions)**:
> 1. **C1 - Behavior Verifier & 35-Sample Dataset**: Bộ kiểm chứng hành vi 3 trạng thái (`BUILD_FAIL`, `UNDETERMINED`, `PASSED_TEST`) ngăn ngừa né tránh ảo (False Positive Evasion) và tập 35 mẫu C chuẩn MITRE ATT&CK.
> 2. **C2 - Proposed Optimization Framework**: Bộ điều phối chi phí nhận thức (C2 Coordinator) + Tối ưu đa mục tiêu (NSGA-II) + Phản hồi ngữ nghĩa (Semantic Reflexion qua Qwen 3.8-27b).

---

## 1. Kiến trúc Tổng thể Hệ thống

```
[35 Mẫu C Dataset / sources/dataset/] ───────────────┐
                                                      ▼
                                       ┌─────────────────────────────┐
                                       │    THUẬT TOÁN BIẾN ĐỔI      │
                                       │ - Heuristic / MAB Bandit     │
                                       │ - Genetic Algorithm (GA)    │
                                       │ - Fixed Hybrid (GA + LLM)   │
                                       │ - PROPOSED (C2 + NSGA-II)   │
                                       └──────────────┬──────────────┘
                                                      │ (Sinh biến thể C)
                                                      ▼
                                       ┌─────────────────────────────┐
                                       │ C1: BEHAVIOR VERIFIER GATE  │
                                       │ 1. Biên dịch chéo MinGW-w64 │
                                       │ 2. Sandbox (VM / Wine)      │
                                       │ 3. Check CRC32 c1_proof.txt │
                                       └──────────────┬──────────────┘
                                                      │
                       ┌──────────────────────────────┴──────────────────────────────┐
                       ▼                                                             ▼
           [BUILD_FAIL / UNDETERMINED]                                         [PASSED_TEST]
              (Crash, Loop, Lỗi ASM)                                       (100% Bảo toàn hành vi)
                       │                                                             │
                       ▼                                                             ▼
                Fitness = 0.0                                          [Đưa vào 4-5 Detector Engines]
           (Đào thải ngay lập tức,                                       ├─ ClamAV (Chữ ký truyền thống)
            không truy vấn detector)                                     ├─ EMBER 2024 (LightGBM PE Tree)
                                                                         ├─ MalConv (Raw-byte CNN)
                                                                         └─ CAPE Sandbox (Dynamic score)
                                                                                     │
                                                                                     ▼
                                                                        [Đa mục tiêu Pareto Front]
                                                                        Fitness cao nhất + Gọn nhất
```

---

## 2. Cấu trúc Thư mục

- `sources/dataset/`: 35 mẫu C chuẩn chia đều vào 7 nhóm kỹ thuật MITRE ATT&CK:
  - `g1_process_injection`: Local Thread, Remote Thread, Early Bird APC, Local Section, Fiber Injection.
  - `g2_execution_hijacking`: DLL Search Order, VEH Hijack, COM Hijack, URL Protocol, IFEO Debugger.
  - `g3_api_hook_evasion`: PEB API Resolve, Hash DJB2, Hash CRC32, Hash Jenkins, Hash ROTR32.
  - `g4_anti_analysis`: PEB Debugger, PEB NtGlobalFlag, RDTSC Timing, Sleep Acceleration, CPUID Hypervisor.
  - `g5_recon_scraping`: Process Enum (TH32/PSAPI), SysInfo, NetAdapter Discovery, Registry OS Query.
  - `g6_c2_network`: HTTP WinINet (GET/POST), HTTP WinHTTP, TCP Winsock, UDP Winsock.
  - `g7_benign_controls`: File CRUD, Matrix Benchmark, Thread Pool, SHA256 Hash, Memory Monitor.
  - `shared/c1_proof.h`: Thư viện tính và ghi canary proof token dạng `SAMPLE_ID|TECHNIQUE|TIMESTAMP|CRC32`.
- `sources/verifier/`: Công cụ kiểm chứng độc lập cross-platform (`verifier.py`, `verifier.ps1`, `test_verifier.ps1`).
- `sources/pipeline/`: `vmrun_verifier.py` (điều khiển kiểm chứng tự động qua VMware Workstation hoặc isolated Wine sandbox) và `mock_c2_server.py`.
- `pipeline/proposed/`: Thuật toán Proposed Method (`C2 Coordinator` + `NSGA-II` đa mục tiêu + `Qwen 3.8-27b Reflexion`).
- `pipeline/ga_only/`: Baseline Genetic Algorithm thuần túy và module tính điểm `static_score.py` (tích hợp Verifier gate).
- `pipeline/bandit/`: Baseline Multi-Armed Bandit (Thompson Sampling).
- `pipeline/hybrid_fixed/`: Baseline lai ghép cố định (EoH-inspired GA + LLM).
- `pipeline/single_agent/`: Baseline Single-Agent Reflexion.
- `baseline_results/comprehensive_matrix/`: Bảng dữ liệu kết quả thực nghiệm toàn diện dạng JSON, CSV và TSV.

---

## 3. Bảng Kết quả Thực nghiệm Toàn diện (Baselines vs Proposed)

Toàn bộ kết quả thực nghiệm đối đầu trên các nhóm kỹ thuật C1 với cổng Behavior Verifier:

| Target ID | MITRE Group / Kỹ thuật | Phương pháp | Fitness | EMBER Score | ClamAV | MalConv | Behavior Verifier (C1) | Đánh giá |
|---|---|---|---|---|---|---|---|---|
| **`g3_02_hash_djb2`** | API Hook Evasion (TA0005) | **Original (Ground Truth)** | 0.8016 | 0.5951 | NO_ALERT | 1.70E-11 | **PASSED_TEST** | Gốc |
| | | Multi-Armed Bandit (MAB) | **0.8320** | **0.5039** | NO_ALERT | 1.76E-11 | **PASSED_TEST** | Cải thiện |
| | | Genetic Algorithm (GA-Only) | **0.8320** | **0.5039** | NO_ALERT | 1.76E-11 | **PASSED_TEST** | Cải thiện |
| | | Fixed Hybrid (GA + LLM) | **0.8320** | **0.5039** | NO_ALERT | 1.76E-11 | **PASSED_TEST** | Cải thiện |
| | | **Proposed (C2 + NSGA-II + Qwen)** | **0.8320** | **0.5039** | NO_ALERT | 1.76E-11 | **PASSED_TEST** | **Tối ưu Pareto** (0% phình) |
| **`g4_01_peb_debugger`** | Anti-Analysis (TA0005) | **Original (Ground Truth)** | 0.7388 | 0.7836 | NO_ALERT | 5.87E-13 | **PASSED_TEST** | Gốc |
| | | Multi-Armed Bandit (MAB) | 0.0000 | 1.0000 | NO_ALERT | N/A | `FAIL` | Bị loại |
| | | Genetic Algorithm (GA-Only) | 0.0000 | 1.0000 | NO_ALERT | N/A | `UNDETERMINED` | Bị loại |
| | | Fixed Hybrid (GA + LLM) | 0.0000 | 1.0000 | NO_ALERT | N/A | `UNDETERMINED` | Bị loại |
| | | Proposed (C2 + NSGA-II + Qwen) | 0.0000 | 1.0000 | NO_ALERT | N/A | `UNDETERMINED` | Bị loại |
| **`g7_01_file_crud`** | Benign Control (System CRUD) | **Original (Ground Truth)** | 0.7261 | 0.8218 | NO_ALERT | 1.25E-09 | **PASSED_TEST** | Gốc |
| | | Multi-Armed Bandit (MAB) | 0.0000 | 1.0000 | NO_ALERT | N/A | `FAIL` | Bị loại |
| | | Genetic Algorithm (GA-Only) | 0.0000 | 1.0000 | NO_ALERT | N/A | `UNDETERMINED` | Bị loại |
| | | Fixed Hybrid (GA + LLM) | 0.0000 | 1.0000 | NO_ALERT | N/A | `FAIL` | Bị loại |
| | | **Proposed (C2 + NSGA-II + Qwen)** | **0.7087** | 0.8740 | NO_ALERT | 3.29E-11 | **PASSED_TEST** | **Duy nhất sống sót** (-1.76% size) |

*Tệp định dạng bảng tính đã được kết xuất sẵn tại:*
- CSV: `baseline_results/comprehensive_matrix/benchmark_results.csv`
- TSV: `baseline_results/comprehensive_matrix/benchmark_results.tsv`
- JSON: `baseline_results/comprehensive_matrix/comprehensive_summary.json`

---

## 4. Hướng dẫn Chạy Thử nghiệm

### 1. Kích hoạt môi trường Python ML
```bash
source ~/Documents/venv/bin/activate
```

### 2. Chạy kiểm thử toàn bộ Unit Test (Hermetic & Mock-based)
```bash
python3 -m unittest discover -s pipeline/tests -p 'test_*.py'
```

### 3. Kiểm chứng 1 mẫu đơn lẻ qua Behavior Verifier
```bash
# Kiểm chứng trực tiếp qua module vmrun_verifier
python3 sources/pipeline/vmrun_verifier.py --sample g3_02_hash_djb2

# Hoặc chấm điểm tích hợp cùng 3 detector tĩnh
python3 -m pipeline.ga_only.static_score sources/dataset/g3_api_hook_evasion/g3_02_hash_djb2.c --engines clamav,ember,malconv
```

### 4. Chạy Thuật toán Proposed Method trên mẫu mới
```bash
python3 -m pipeline.proposed run sources/dataset/g3_api_hook_evasion/g3_02_hash_djb2.c \
  --pool pipeline/mutators/native_pool.json \
  --output baseline_results/proposed_run/ \
  --score-command "python3 -m pipeline.ga_only.static_score {source} --engines clamav,ember,malconv" \
  --population-size 4 --generations 2 --model "cf/@cf/qwen/qwen3.8-27b"
```

### 5. Chạy So sánh Toàn diện (Comprehensive Benchmark Runner)
```bash
python3 run_comprehensive_matrix.py
```

