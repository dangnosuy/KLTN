# Danh mục Dataset Kỹ thuật Nâng cao

> Đây là bộ tham chiếu cũ. Thiết kế V2 và bốn chương trình đối chứng nằm ở
> [dataset V2](../v2/README.md). Nhãn sẵn sàng của bộ cũ không tự chứng nhận C1 V2.

Tài liệu này mô tả mã nguồn tại `dataset/advanced/sources/` và đầu ra biên dịch tại
`dataset/advanced/build/`. Đây là tập chương trình C mô phỏng hành vi thực thi
và thao tác bộ nhớ trên Windows, phục vụ đánh giá độ bền vững của detector trong
khóa luận. Chúng không phải tập mã độc thực tế và chỉ được chạy trong Windows VM
cô lập qua `pipeline/vmrun_pipeline.py`.

`dataset/advanced/build/manifest.json` là nguồn dữ liệu chuẩn về trạng thái mẫu.
Pipeline chỉ tự động lấy các mẫu có `benchmark_ready: true` khi nhận đầu vào là
thư mục; cách này ngăn prototype hoặc mẫu thiếu dependency bị tính nhầm là kết
quả né tránh.

Mỗi entry là một package benchmark: file `.exe` là entrypoint và `companions`
là các artifact phải được đặt cạnh loader, chẳng hạn `payload.dll`. Pipeline
hash, copy và tương quan evidence của từng artifact nhưng chỉ tạo một verdict
cho package trên mỗi engine. DLL companion phải có telemetry load trước khi
`NO_ALERT` được xem là kết quả hợp lệ.

Các mẫu `benchmark_ready` dùng profile `high_signal_v1`: payload chạy
`ipconfig /all`, lưu `canary_ipconfig.txt`, tạo `c1_pass.txt`, rồi gửi kết quả
về listener `192.168.183.1:18080` để xác nhận thực thi độc lập với ảnh chụp. Pipeline
chỉ truy vấn detector sau khi thấy proof này; thiếu proof được ghi là
`EXECUTION_FAILURE`, không phải bypass hay `NO_ALERT`.

## Build lại bộ mẫu

```bash
bash dataset/advanced/build.sh
```

Script dọn các `.exe` và `.dll` cũ trong `build/`, build lại hai DLL phụ trợ,
tái sinh `sources/common/embedded_dll.h` từ `payload.dll`, rồi build toàn bộ 21
executable. `manifest.json` được giữ lại vì là registry của pipeline.

## 1. Vai trò trong khóa luận

| Thành phần | Dataset đóng góp gì | Kết quả cần dùng |
|---|---|---|
| C1 - Kiểm chứng hành vi | Cung cấp chương trình gốc có kỹ thuật và dependency xác định để kiểm chứng build/chạy trước khi query detector. | `Build Fail`, `Passed Behavioral Test`, hoặc `Undetermined` |
| C2 - Tìm kiếm thích nghi | Là hạt giống để tạo biến thể C và so sánh hiệu quả né tránh với chi phí query/token. | Chi phí, trạng thái hợp lệ, kết quả detector |
| C3 - Chuyển giao | Cho phép tách theo chương trình gốc/kỹ thuật để đánh giá trên detector hoặc chương trình held-out. | Tỷ lệ phát hiện/né tránh trên từng nhóm |
| Detector | Đo static observation, telemetry tiến trình, alert theo rule/hành vi và phát hiện Defender. | Telemetry, alert, verdict, lỗi hạ tầng |

**Nguyên tắc diễn giải:** chỉ một mẫu đã qua C1, có telemetry xác nhận chạy,
và không có alert phù hợp mới được xem là ứng viên né tránh. `INFRA_FAILURE`,
không có telemetry, hoặc `Undetermined` không phải là né tránh.

## 2. Cấu trúc và quy ước

| Vị trí | Nội dung | Vai trò |
|---|---|---|
| `sources/baseline/` | 2 nguồn đối chứng thực thi cục bộ | Mốc telemetry và static observation |
| `sources/resolution/` | 2 kỹ thuật phân giải API/module | Nhóm loader support |
| `sources/injection/` | 5 nguồn injection/APC/thread context | Nhóm hành vi tiến trình |
| `sources/experimental/` | 12 prototype hoặc cơ chế chưa hoàn thiện | Backlog phát triển, không vào batch |
| `sources/common/` | Payload, DLL source và header dùng chung | Dependency được kiểm soát tập trung |
| `build/` | 21 PE `.exe`, DLL đi kèm và manifest | Đầu vào trực tiếp của VM pipeline |
| `build/manifest.json` | `source`, `technique`, `fidelity`, `benchmark_ready`, `companions` | Registry truy vết mẫu và điều khiển batch |

| Trạng thái manifest | Ý nghĩa | Có tự chạy khi truyền thư mục? |
|---|---|---|
| `baseline` / `reference_flow` | Luồng thực thi đã được chọn làm đối chứng benchmark | Có |
| `support_technique` | Kỹ thuật hỗ trợ/loader, không tự nó đại diện cho một injection hoàn chỉnh | Có, nhưng báo cáo riêng |
| `prototype*`, `simulation*`, `blocked*` | Cơ chế mới mô phỏng, thiếu bước thực thi hoặc chưa xác minh được | Không |

## 3. Danh mục đầy đủ

| Mẫu | Kỹ thuật/cơ chế chính | Payload hoặc dependency | Trạng thái | Ý nghĩa đánh giá |
|---|---|---|---|---|
| `local_exec.exe` | Cấp phát vùng nhớ cục bộ và thực thi payload trong tiến trình hiện tại | `payload.h` | Baseline, sẵn sàng | Đường cơ sở cho telemetry thực thi bộ nhớ cục bộ |
| `map_view.exe` | Ánh xạ section vào bộ nhớ và thực thi cục bộ | `payload.h` | Reference flow, sẵn sàng | So sánh với cấp phát RWX cục bộ trực tiếp |
| `api_hash_djb2.exe` | Phân giải API bằng băm DJB2 rồi thực thi cục bộ | `payload.h` | Support technique, sẵn sàng | Đo ảnh hưởng của cách phân giải API lên detector |
| `peb_walk.exe` | Duyệt PEB để tìm module/API rồi thực thi cục bộ | `payload.h` | Support technique, sẵn sàng | Đối chứng cho resolver không dùng chuỗi API trực tiếp |
| `crt_inject.exe` | Ghi payload vào tiến trình khác và tạo remote thread | `payload.h` | Reference flow, sẵn sàng | Mốc đối chứng cho remote process injection |
| `early_bird.exe` | Xếp APC vào primary thread của tiến trình đang suspended | `payload.h` | Reference flow, sẵn sàng | Đo telemetry/alert của APC injection sớm |
| `thread_hijack.exe` | Suspend thread, đổi context rồi resume | `payload.h` | Reference flow, sẵn sàng | Đo kỹ thuật chuyển hướng luồng không tạo remote thread mới |
| `classic_dll_injection.exe` | Nạp DLL vào tiến trình khác qua luồng từ xa | `payload.dll` | Reference flow, sẵn sàng | Đối chứng DLL injection có file companion |
| `apc_queue.exe` | Biến thể APC trùng ý tưởng với Early Bird | `payload.h` | Prototype, loại khỏi batch | Tránh nhân đôi kỹ thuật trước khi có khác biệt kiểm chứng được |
| `module_stomp.exe` | Ghi đè entry point của module trong tiến trình hiện tại | `c1_return_payload.h` | Reference flow C1, sẵn sàng | Thread return sạch, loader xác nhận marker sau khi entry point module chạy |
| `process_hollow.exe` | Tạo tiến trình suspended, thay thế vùng thực thi bằng payload | `c1_return_payload.h` | Prototype, completion chưa xác minh | Raw stub không thể thay thế primary PE image; cần payload PE hợp lệ để hoàn thiện đúng kỹ thuật |
| `reflective_injection.exe` | Manual map DLL từ buffer trong tiến trình hiện tại | `embedded_dll.h` | Reference flow, sẵn sàng | C1 pass: fixture DLL không TLS, import/relocation, quyền section và entry point đã xác minh |
| `threadless_inject.exe` | Sửa export cục bộ (mô phỏng) | `payload.h` | Simulation, loại khỏi batch | Không phải remote threadless injection hoàn chỉnh |
| `ekko_sleep.exe` | Timer queue/sleep mô phỏng | `payload.h` | Simulation, loại khỏi batch | Không phải triển khai Ekko đầy đủ |
| `hells_gate.exe` | Truy tìm syscall number | `payload.h` | Prototype, không direct syscall | Chỉ là bước resolver để phát triển tiếp |
| `indirect_syscall.exe` | Tìm syscall gadget | `payload.h` | Prototype, không indirect syscall | Chỉ là bước resolver để phát triển tiếp |
| `atombombing.exe` | Staging dữ liệu qua Global Atom Table | `payload.h` | Prototype, khôi phục payload chưa hoàn chỉnh | Payload nhị phân hiện chưa được tái tạo an toàn/chính xác |
| `mockingjay.exe` | Tìm vùng RWX trong DLL rồi ghi payload | `rwx_module.dll`, `c1_return_payload.h` | Reference flow C1, sẵn sàng | Companion `.rwx_sec` có quyền RWX thật; thread return sạch và marker xác nhận thực thi |
| `process_ghosting.exe` | Tạo image section từ file delete-pending | DLL nhúng | Prototype, không tạo/chạy process | Chỉ chứng minh bước section creation |
| `process_doppelganging.exe` | Tạo image section qua NTFS transaction | DLL nhúng | Prototype, không tạo/chạy process | Chỉ chứng minh bước section creation |
| `process_herpaderping.exe` | Tạo image section rồi thay đổi nội dung file | DLL nhúng | Prototype, không tạo/chạy process | Chỉ chứng minh bước section creation |

Tổng cộng: **21 executable**, gồm **11 mẫu sẵn sàng benchmark** và **10
prototype/blocked**. Trong 11 mẫu sẵn sàng có 9 mẫu thực thi/injection và 2 mẫu
support technique (API hash, PEB walk), cần được phân tích thành nhóm riêng.

## 4. Tập benchmark hiện hành

Khi chạy trực tiếp thư mục `dataset/advanced/build/`, pipeline chỉ chọn:

| Nhóm | Mẫu |
|---|---|
| Baseline thực thi cục bộ | `local_exec.exe`, `map_view.exe` |
| Resolver/loader support | `api_hash_djb2.exe`, `peb_walk.exe` |
| Process injection | `crt_inject.exe`, `early_bird.exe`, `thread_hijack.exe` |
| DLL injection | `classic_dll_injection.exe` cùng `payload.dll` |
| Local manual map | `reflective_injection.exe` |
| Local module / RWX section execution | `module_stomp.exe`, `mockingjay.exe` |

Lệnh chạy benchmark trong VM cô lập:

```bash
python3 pipeline/vmrun_pipeline.py doctor --engines elastic,wazuh,defender
python3 pipeline/vmrun_pipeline.py run dataset/advanced/build/ \
  --engines elastic,wazuh,defender
```

Có thể chạy một mẫu prototype **chỉ để phát triển/C1** bằng đường dẫn `.exe`
trực tiếp. Nó không được đưa vào thống kê chính thức cho tới khi manifest đổi
`benchmark_ready` thành `true` sau khi đã xác minh hành vi và dependency.

Kiểm tra C1 của các mẫu đang phát triển với exit code và marker `c1_pass.txt`:

```bash
source pipeline/vmrun.env.example
export VMRUN_SNAPSHOT_WAZUH=wazuh_benchmark_ready_20261015
python3 dataset/advanced/c1_smoke.py --snapshot "$VMRUN_SNAPSHOT_WAZUH"
```

`c1_return_payload.h` là stub `RET` chỉ dùng cho C1 của Module Stomp và
Mockingjay. Nó tách việc chứng minh primitive thực thi khỏi shellcode fixture,
để process phải return sạch trước khi mẫu được đưa vào benchmark.

## 5. Cách đọc kết quả detector

| Engine | Điều cần kiểm tra | Diễn giải kết quả |
|---|---|---|
| Elastic Defend | Telemetry tiến trình theo SHA-256 trước, sau đó behavior alert | Alert file/ML chỉ là quan sát phụ; kết luận behavior chỉ dựa trên behavior alert sau khi có telemetry |
| Wazuh + Sysmon | Telemetry Sysmon theo mẫu, sau đó rule/alert tương quan | Có telemetry nhưng không có alert là không phát hiện cho rule hiện tại, không mặc định là lỗi pipeline |
| Windows Defender | Trạng thái phát hiện/chặn mẫu | Chỉ đánh giá detected/clean; không yêu cầu phân loại behavior |
| Chung | Package SHA-256, hash từng artifact, thời điểm chạy, lỗi copy/hash, health và report campaign | `INFRA_FAILURE`, `EXECUTION_FAILURE` hoặc thiếu telemetry phải loại khỏi mẫu số benchmark |

## 6. Quy trình báo cáo đề xuất

1. Khóa phiên bản compiler, hash của `.exe`, snapshot VM và phiên bản policy/rule detector.
2. Chạy C1 cho từng chương trình gốc/biến thể; chỉ mẫu `Passed Behavioral Test` mới vào batch detector.
3. Chạy detector theo từng engine từ snapshot độc lập, lưu campaign ID và report thô.
4. Tách số liệu theo: kỹ thuật, trạng thái C1, detector, telemetry có/không, behavior alert và Defender verdict.
5. Báo cáo riêng mẫu baseline/reference, support technique và held-out; không gộp prototype vào tỷ lệ né tránh.

## 7. Giới hạn phải nêu trong khóa luận

- Nhiều mẫu dùng chung `payload.h`; detector có thể phát hiện đặc trưng payload thay vì kỹ thuật loader. Cần báo cáo static/ML tách khỏi behavior telemetry.
- `NO_ALERT` chỉ có ý nghĩa sau khi đã có bằng chứng chương trình chạy và telemetry xuất hiện; nếu không, kết quả là `Undetermined` hoặc lỗi hạ tầng.
- 13 prototype hiện chỉ là backlog phát triển kỹ thuật, không phải bằng chứng rằng một kỹ thuật đã né được EDR/AV.
- Đây là các PoC hành vi mô phỏng trong VM cô lập. Kết quả không suy rộng thành nhận định về malware thực tế hay mọi cấu hình detector.
- Manifest đã quản lý trạng thái đầu ra, nhưng build automation và test suite C1 riêng cho từng mẫu vẫn cần được hoàn thiện trước khi mở rộng dataset thành tập 20-30 chương trình gốc và split in-domain/held-out chính thức.
