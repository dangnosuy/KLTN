# Pipeline Detector Chính

## Mục tiêu

Nhận một file `.exe` hoặc một thư mục, đánh giá bằng đúng 5 detector:

| Engine | Nhánh | Cách quyết định |
|---|---|---|
| `clamav` | Static AV | Kết quả `clamscan` và threat name |
| `ember` | Static ML | Score ≥ 0.5 |
| `malconv` | Static ML | Score ≥ 0.5; checkpoint Elastic EMBER, đọc tối đa 1 MiB đầu |
| `defender` | Static AV offline | Custom scan bằng `MpCmdRun.exe`, không chạy sample |
| `cape` | Behavior | Behavior score riêng ≥ 4/10 |

Đây là cụm chính. Held-out để riêng, không dùng capa/Quo Vadis, SOREL,
YARA, Elastic Defend hoặc Wazuh trong luồng này. Pipeline cũ vẫn giữ nguyên.
CAPE tái sử dụng hàm chấm điểm trong `heldout/cape_behavior_score.py`, không
chạy cụm held-out. `malscore` gốc chỉ lưu tham khảo.

## Luồng xử lý

```text
EXE → kiểm tra PE và manifest → hash và bản input cố định trong campaign
    → ClamAV → EMBER → MalConv → Defender CLI → CAPE → JSON/CSV/bảng terminal
```

Chạy theo engine: mỗi engine xử lý hết input trước khi sang engine tiếp theo.
Defender revert một lần đầu campaign, chỉ quét file, xóa staging sau mỗi lượt,
rồi tắt VM trước CAPE. CAPE tự điều phối VM/snapshot cho từng task.
Không dừng chỉ vì một detector phát hiện; lỗi một engine không biến thành clean
và không ngăn những engine độc lập còn lại.
Không chạy pipeline VMware cũ đồng thời với pipeline này trên cùng VM; lock của
module mới không được các script cũ sử dụng.

Input có DLL dùng `manifest.json` đặt cạnh EXE:

```json
{
  "samples": {
    "loader.exe": {"companions": ["payload.dll"]}
  }
}
```

Không tự đoán DLL theo tên, không lấy toàn bộ file trong thư mục. Thiếu companion
thì từ chối input. Các scanner tĩnh quét EXE và từng companion; verdict package
là phát hiện nếu ít nhất một artifact bị phát hiện và tất cả lượt quét hợp lệ.
Report giữ verdict từng artifact; score ML của package là score cao nhất.
CAPE nhận ZIP chứa đủ các file và option `file=loader.exe`, không tự chạy DLL.
Hash package thay đổi nếu tên hoặc nội dung bất kỳ artifact nào thay đổi.

## Môi trường

- Linux: Python 3.11+, `requests`, `clamscan` và database ClamAV.
- Model: dùng các checkpoint hiện có ở đường dẫn trong `config.example.json`.
- Worker ML: dùng `~/Documents/venv/bin/python3`, đã có LightGBM, thrember,
  NumPy và TensorFlow. Không tự tải model hoặc nâng dependency khi chạy.
- Defender: VMware Tools, quyền quản trị guest, snapshot `normal_real`.
- CAPE: API tại `http://localhost:8000`, Windows machine đã đăng ký, worker và
  processor hoạt động. Server từ xa bắt buộc HTTPS với certificate tin cậy.
- Không thực thi sample trên Linux host. Chỉ CAPE có trách nhiệm chạy sample.

Mọi đường dẫn tương đối trong config được tính từ root workspace, không từ vị trí
file JSON. `--config` nhận cấu hình đầy đủ hoặc chỉ các trường muốn thay đổi.
Credentials không có trong JSON; Defender dùng `VMRUN_VMX`, `VM_GUEST_USER`,
`VM_GUEST_PASSWORD`, `VMRUN_VM_PASSWORD` nếu VM mã hóa, và CAPE dùng
`CAPE_API_TOKEN` nếu bật token authentication. Defender dùng transport VMware tối
giản nội bộ; không gọi Elastic hoặc Wazuh.

## Chuẩn bị Defender offline

Thực hiện một lần bằng PowerShell Administrator trong VM dành riêng cho scanner:

```powershell
New-Item -ItemType Directory -Path C:\DetectorScans -Force
Add-MpPreference -ExclusionPath 'C:\DetectorScans'
Set-MpPreference -MAPSReporting 0 -SubmitSamplesConsent 2 -DisableBlockAtFirstSeen $true
Get-MpComputerStatus
Get-MpPreference | Select-Object MAPSReporting, SubmitSamplesConsent, DisableBlockAtFirstSeen, ExclusionPath
```

Giữ Defender engine/service hoạt động; không cần tắt real-time toàn máy. Staging
exclusion chỉ dành cho VM lab để file không bị on-access quarantine trước CLI.
Custom scan `-DisableRemediation` vẫn quét file trong exclusion và không thực hiện
remediation. Phải loại staging khỏi mọi cơ chế autorun/watcher cũ.

Tạo/cập nhật snapshot `normal_real` sau khi chuẩn bị. Ghim engine và signature
database trong một campaign: cập nhật trước chiến dịch, không cập nhật giữa chừng.
Không dùng VM này duyệt web, chạy mẫu hoặc cho phép outbound Internet. API host
và VMware Tools không phải đường gửi mẫu cho Microsoft.

Doctor chỉ đọc cấu hình, không tự sửa policy hoặc boot/revert VM. Vì vậy cần mở
VM scanner nếu muốn kiểm tra Defender bằng doctor; lệnh `run` mới revert và
kiểm tra lại snapshot trước khi copy input. Tamper Protection/GPO có thể từ chối
thay đổi; khi đó doctor sẽ không READY, không được bỏ qua gate này.

[Tài liệu Microsoft về MpCmdRun](https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus):
`-DisableRemediation` trả detection trong CLI output, không phải Event Log/UI.
Exit code `2` có thể là lỗi quét; không được mặc định xem mọi code `2` là detect.
Parser hiện hỗ trợ output tiếng Anh; output khác không nhận diện được trả lỗi.

## Cách chạy

Chạy từ root workspace:

```bash
source ~/Documents/venv/bin/activate
source pipeline/detectors/vmware.env.example
python3 -m pipeline.detectors doctor --config pipeline/detectors/config.example.json
python3 -m pipeline.detectors run dataset/advanced/build/crt_inject.exe \
  --config pipeline/detectors/config.example.json --campaign thesis-r01
```

Chỉ kiểm tra/scanner local khi VM và CAPE đang tắt:

```bash
python3 -m pipeline.detectors doctor --engines clamav,ember,malconv
python3 -m pipeline.detectors run dataset/advanced/build/crt_inject.exe \
  --engines clamav,ember,malconv --campaign static-r01
```

Với thư mục, thay đường dẫn EXE bằng thư mục input; không đặt thư mục output bên
trong input. Mặc định chạy đủ 5 engine; `--engines` dùng danh sách phân cách dấu
phẩy. Engine không được chọn là `SKIPPED`, không được tính là không phát hiện.
Entry có `benchmark_ready: false` trong manifest cạnh EXE bị loại khi quét thư mục.
Thiếu trường này vẫn giữ tương thích với manifest tối giản. Quét EXE trực tiếp
vẫn được cho chẩn đoán, không tự chứng nhận đủ điều kiện thực nghiệm.
Không tự start/stop service CAPE, ClamAV hay EDR trên host.

| Tham số/cấu hình | Mặc định | Ý nghĩa |
|---|---|---|
| `--campaign` | ID UTC tự sinh | Cùng ID để resume; ID mới để quét lại toàn bộ |
| `--config` | Defaults trong module | JSON cấu hình, không chứa mật khẩu |
| `--engines` | Cả 5 | Giới hạn engine để kiểm tra riêng |
| `--c1` | Không có | JSON C1 tùy chọn cho đúng một EXE |
| `static.timeout` | 120 giây | Mỗi scanner/artifact |
| `defender.timeout` | 180 giây | Chờ custom scan, không phải detonation |
| `cape.analysis_timeout` | 120 giây | Thời gian phân tích yêu cầu cho CAPE |
| `cape.timeout` | 900 giây | Tổng chờ task, gồm queue và processing |
| `cape.poll_interval` | 10 giây | Khoảng poll, có log tiến trình |
| `cape.machine` | Rỗng | Cho scheduler CAPE chọn Windows machine |
| `cape.threshold` | 4 | Ngưỡng behavior detection |

## Kết quả và resume

`pipeline/reports/detectors/<campaign>/` chứa:

- `manifest.json`: config, hash model/code, phiên bản detector và danh sách package.
- `inputs/`: bản input cố định, không phải file được phép thực thi trên host.
- `samples/<package_sha256>.json`: đúng 5 bản ghi engine và C1 tùy chọn.
- `evidence/`: kết quả scanner từng artifact, `cape-task.json` và CAPE report gốc.
- `summary.json`, `summary.csv`: bảng tổng hợp cập nhật sau từng lượt quét.

Mỗi engine có `status`, `verdict`, `detected`, duration, version, score/threshold
nếu có và đường dẫn evidence. `COMPLETED + NO_ALERT` chỉ nói detector không báo
trong điều kiện đã ghi, không khẳng định benign hay bypass. `ERROR` và
`INFRA_FAILURE` luôn có `detected=null`; không đưa vào mẫu số đánh giá phát hiện.
`SKIPPED` cũng có `detected=null`.

Resume bỏ qua kết quả `COMPLETED`, chỉ chạy lại lỗi/engine chưa chọn. Kết quả
được tái sử dụng là lịch sử campaign, không phải phép quét mới với database hiện
tại. Đổi config, model hoặc code yêu cầu campaign mới. Khi thực hiện lượt quét
mới trong campaign cũ, engine/database phải khớp phiên bản đã ghim.

CAPE lưu task ID ngay khi submit thành công. Timeout poll giữ task để resume,
không tạo task mới. Task failed vẫn dùng task cũ: cần điều tra hoặc tạo campaign
mới để phân tích mới. Nếu POST mất phản hồi, pipeline giữ `SUBMITTING` và từ chối
gửi lại để tránh duplicate; đối chiếu `custom=detectors-<package_sha256>` trên
CAPE, xác nhận task đúng input rồi bổ sung `task_id` vào `cape-task.json` trước
khi resume. Không xóa state khi chưa biết server đã nhận mẫu hay chưa.

CLI trả code `0` nếu các engine được chọn đều hoàn tất (phát hiện cũng là kết quả
thành công), `2` khi có lỗi, `130` khi ngắt. Chạy subset có thể trả `0` nhưng
summary vẫn `PARTIAL` vì chưa đủ 5 engine.

## C1 và giới hạn khoa học

`--c1` nhận JSON từ module bên ngoài:

```json
{"sha256": "<SHA256 cua EXE>", "status": "PASS"}
```

Status hỗ trợ `PASS`, `BUILD_FAIL`, `UNDETERMINED`; hash phải đúng EXE. Pipeline
chỉ lưu metadata này, không tự chạy hoặc thay thế C1 và không ngăn phép quét độc
lập khi C1 chưa PASS. Không tự tính evasion rate hoặc đưa kết luận bypass.

Behavior score CAPE là chỉ số rủi ro dựa trên runtime rule, không phải xác suất.
Đã loại static/YARA khỏi quyết định. Process tree rỗng, chỉ có process nền hoặc
không có API call quy thuộc được cho sample/lineage trả `INFRA_FAILURE`.
Những signature runtime cấp task không có PID vẫn dùng policy của scorer cũ;
đây không phải chứng minh hoàn chỉnh về hành vi hay tương đương chức năng.

Các ngưỡng 0.5/4 là policy ban đầu, cần hiệu chỉnh trên validation set riêng rồi
đóng băng. Defender quét tĩnh không đồng nghĩa chỉ dùng signature: engine còn có
thể dùng heuristic/ML cục bộ. Database ClamAV/Defender cũ ảnh hưởng độ bao phủ;
luôn ghi phiên bản và kiểm tra ngày cập nhật trước thực nghiệm.

## Kiểm thử

```bash
python3 -m unittest pipeline.tests.test_detectors
python3 -m unittest discover -s pipeline/tests -p 'test_*.py'
```

Mock test kiểm tra kết quả 5 engine, lỗi/timeout không thành clean, threshold biên,
Defender không launch sample, EXE/DLL, CAPE hash/task/entrypoint, telemetry thiếu,
resume không submit trùng, lock và config/model bị đổi.
Trước pilot thật cần doctor READY, kiểm tra file PE vô hại, EICAR cho AV (không
đưa EICAR vào đầu vào EXE của ML), rồi mới chạy bộ 5 mẫu đã được phê duyệt trong
lab. Không dùng screenshot thay cho runtime evidence.
