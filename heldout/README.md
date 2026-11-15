# Held-out Detector Cluster

> Cập nhật cụm chính: CAPE đã được chọn làm detector behavior trong
> [pipeline mới](../pipeline/detectors/README.md), nên **không còn là held-out**
> cho các thí nghiệm sử dụng phản hồi CAPE. Scorer vẫn đặt ở đây để tái sử dụng
> và tương thích với report cũ. Detector behavior held-out thay thế sẽ chốt sau.

Cụm này được tách khỏi pipeline phát triển để đánh giá RQ3 sau khi đã đóng băng
mẫu. Không sử dụng kết quả trong thư mục này làm fitness, reward hoặc feedback
cho quá trình sinh và biến đổi mẫu.

## Detector

| Nhánh | Detector | Phiên bản/cấu hình | Đầu ra chính |
|---|---|---|---|
| Static rule | Mandiant capa | 10.0.0, embedded official rules | capability, ATT&CK ID, rule match |
| ML | Quo Vadis | pretrained emulation-only MLP | score, verdict, số API được giả lập |
| Behavior | Chưa chốt detector thay thế | CAPE chuyển sang cụm chính | sẽ triển khai riêng |

Quo Vadis sử dụng Speakeasy để giả lập PE, không chạy native sample trên máy
Linux. Môi trường Python 3.9 và model được cài riêng trong `heldout/.tools/`.

CAPE vẫn giữ nguyên `malscore` gốc để tham khảo. `cape_behavior_score.py` tạo
thêm điểm 0-10 chỉ từ signature có bằng chứng runtime, giới hạn điểm theo từng
nhóm để tránh cộng trùng và cộng 1 điểm khi có đủ chuỗi thread, DLL load và
process creation từ vùng nhớ không thuộc module.

## Quyết định phiên bản

- [capa 10.0.0](https://github.com/mandiant/capa/releases/tag/v10.0.0) được dùng
  dưới dạng standalone release vì gói `flare-capa` trên PyPI không kèm embedded
  rules.
- [Quo Vadis](https://github.com/dtrizna/quo.vadis) là research prototype và
  upstream chỉ xác nhận Python 3.8-3.9. Cấu hình held-out chỉ dùng module
  `emulation`, không dùng lại EMBER hoặc MalConv.
- `speakeasy-emulator==1.5.11` được ghim theo thế hệ model của Quo Vadis. Không
  tự động nâng lên Speakeasy 2.x vì report schema và đường emulation có thể làm
  thay đổi phân phối API đầu vào của model.
- Model, API vocabulary và meta-model đều là pretrained artefact chính thức;
  setup kiểm tra SHA-256 trước khi sử dụng.

## Cài đặt

```bash
bash heldout/setup.sh
python3 heldout/run_heldout.py doctor
```

`setup.sh` ghim phiên bản và kiểm tra SHA-256 của binary/model tải về. Cần có
`curl`, `unzip`, `sha256sum` và `uv`.

## Chạy

Một file:

```bash
python3 heldout/run_heldout.py run dataset/advanced/build/crt_inject.exe
```

Một thư mục:

```bash
python3 heldout/run_heldout.py run dataset/advanced/build/ \
  --output heldout/reports/advanced.json
```

Chấm một report CAPE đã hoàn tất:

```bash
python3 heldout/cape_behavior_score.py \
  /opt/CAPEv2/storage/analyses/10/reports/report.json \
  --output heldout/reports/cape-task-10.json
```

Chỉ chạy một engine:

```bash
python3 heldout/run_heldout.py run dataset/advanced/build/ --engines capa
python3 heldout/run_heldout.py run dataset/advanced/build/ --engines quo-vadis
```

Các tham số:

- `--engines`: `capa`, `quo-vadis`, hoặc danh sách phân cách bằng dấu phẩy.
- `--output`: đường dẫn report JSON.
- `--timeout`: timeout cho mỗi detector/mẫu, mặc định 120 giây.

## Diễn giải kết quả

Capa là capability detector, không phải antivirus nhị phân. Trường `detected`
chỉ đúng khi rule khớp một ATT&CK ID hoặc namespace capability nguy cơ cao trong
`policy.json`; report vẫn lưu toàn bộ rule và ATT&CK ID để phân tích. Policy phải
được hiệu chỉnh trên một validation set riêng rồi đóng băng trước chiến dịch
held-out.

Quo Vadis trả `ERROR` nếu Speakeasy không tạo được API telemetry. Trường hợp này
không được tính là `BENIGN` hoặc bypass. Ngưỡng mặc định là `0.5` và được lưu
trong report.

Quo Vadis công bố đây là prototype pre-alpha và không phát hành toàn bộ raw PE
training set. Vì vậy kết quả của nó cần được trình bày như một held-out research
detector, không phải ground truth hay đại diện cho sản phẩm antivirus thương mại.

Điểm behavior của CAPE là chỉ số rủi ro có thể giải thích, không phải xác suất
malware. `HIGH_RISK` bắt đầu từ 7 điểm, `SUSPICIOUS` từ 4 điểm; report không có
process tree được trả thành `INFRA_FAILURE`, tuyệt đối không tính là bypass.

