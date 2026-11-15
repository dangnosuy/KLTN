# Dataset V2: chương trình C và hợp đồng kiểm chứng

## Trạng thái thật

Đã có catalog pilot 8 seed + 4 đối chứng, công cụ audit 21 source cũ,
bốn đối chứng C vô hại, build container và export có kiểm tra receipt C1.
**Chưa có seed nào được chứng nhận V2. Chưa chạy C1 Windows hoặc benchmark V2.**
Không sửa hoặc nâng cấp cơ chế injection/né phát hiện của các source cũ.
Build/export hiện chỉ hỗ trợ bốn đối chứng; tám seed là danh mục chờ audit độc lập,
không phải tám triển khai V2 đã hoàn thành. Không dùng catalog để tự động cấp PASS.

## Tổ chức

- `catalog.json`: chương trình gốc, vai trò và nhóm nguồn gốc; mọi mẫu hiện thuộc development.
- `research_tracks`: mười nhóm nghiên cứu, trạng thái kỹ thuật hiện tại, source legacy liên quan,
  bằng chứng bắt buộc và giới hạn phạm vi. Đây không phải danh sách bypass.
- `programs/`: bốn control và source DLL phụ trợ, không có shellcode hoặc mạng.
- `common/`: fixture dữ liệu tổng hợp dùng chung, không có framework injection.
- `manage.py`: audit chỉ đọc, build control, export release từ bằng chứng bên ngoài.
- Contract được sinh cạnh EXE trong build, không viết vào source.
- `build/<id>/`: build bất biến, manifest, hash, contract và log compiler.
- `releases/<id>/`: bản đã qua gate, dùng làm input detector.
- Tests dùng chung `pipeline/tests/test_dataset_v2.py`.

Không thêm thư mục rỗng hoặc header generated nếu chưa dùng. Source cũ giữ nguyên.
Prototype là archive theo metadata audit, không bị xóa vật lý.

## Audit và phân nhóm

```bash
python3 dataset/v2/manage.py audit
python3 dataset/v2/manage.py coverage
```

Mỗi dòng có source hash, fidelity cũ, dependency, quyết định V2 và `v2_ready=false`.
Nguồn/giấy phép source cũ chưa được xác minh, phải kiểm tra trước phân phối lại.
`reflective_injection.exe` được catalog gọi đúng phạm vi `local_manual_map_dll`.
API hash và PEB walk là support variant, không tính thêm seed. Mockingjay dùng
fixture RWX nhân tạo nên nằm nhóm dự phòng phụ thuộc môi trường.

`coverage` cho thấy đúng trạng thái của mười hướng nghiên cứu: interception cục bộ
mới là demo một phần; syscall chỉ là resolver; hollowing là prototype chưa xác
minh; manual mapping/thread context chờ C1. Các hướng metadata, debugger và ký
code chỉ có phạm vi control trên artifact/chứng chỉ lab tự sở hữu. Không có track
nào được ghi là "bypass", và một track không được chuyển thành benchmark chỉ vì
có file source hoặc detector không báo.

## Build container cô lập

Tạo image một lần (bước này cần mạng tải package), sau đó khóa image ID cho cả đợt:

```bash
docker build -f dataset/v2/Containerfile -t thesis-dataset-controls .
IMAGE=$(docker image inspect thesis-dataset-controls --format '{{.Id}}')
mkdir -p dataset/v2/build
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --user "$(id -u):$(id -g)" \
  -e BUILD_IMAGE_ID="$IMAGE" --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -v "$PWD:/src:ro" -v "$PWD/dataset/v2/build:/out:rw" \
  "$IMAGE" build-controls --output /out/controls-r01
```

Không gắn Docker socket/credentials vào container. Không chạy PE trên Linux host.
GCC/binutils, flags, image ID, source hash và output hash được lưu trong manifest.
Image recipe dùng package repository tại thời điểm tạo; muốn tái lập phải giữ
**đúng image ID**, không rebuild tag rồi coi là cùng toolchain.
Chạy lại với output ID khác và so `artifact_hashes` của hai manifest để kiểm tra
byte-for-byte. Chưa có kết quả so hai build container ở môi trường hiện tại.
Không build đè output cũ; lỗi trong staging không xóa release có sẵn.

## Hợp đồng C1

Mỗi control chạy trong thư mục riêng sạch và tạo đúng `result.txt` chứa byte:
`dataset-v2:0123456789abcdef` theo sau bằng LF. Exit code phải là 0.
Không thu thập dữ liệu máy thật, không Internet, không shell tương tác.
DLL được nạp bình thường từ đường dẫn cạnh EXE; child chỉ chạy lại EXE của chính
control với đối số cố định. File/result đơn thuần không chứng minh cơ chế.

Runner C1 bên ngoài phải đọc contract, xác minh nội dung file/exit code, process
lineage hoặc module load tương ứng, dọn process và ghi nhận môi trường sạch.
Dataset **không triển khai lại runner C1**. Contract hiện mô tả control; contract
cho tám seed phải được thiết kế và review riêng trước khi mở khả năng export seed.

Đặt `evidence/<program_id>.json` theo định dạng sau, với ít nhất ba run ID khác nhau:

```json
{
  "approval": {
    "package_sha256": "<hash package theo pipeline.detectors.core.package>",
    "contract_sha256": "<hash contract JSON>",
    "mechanism_reviewed": true,
    "reviewer": "<nguoi review doc lap>"
  },
  "runs": [
    {
      "run_id": "<ID duy nhat>",
      "status": "PASS",
      "environment_id": "<snapshot/OS/runner version>",
      "contract_sha256": "<hash contract JSON>",
      "artifact_hashes": {"normal_dll.exe": "<sha256>", "fixture.dll": "<sha256>"}
    }
  ]
}
```

Ví dụ chỉ hiển thị một run; cần ba run thật, không sao chép hoặc tự tạo bằng chứng.
EXE độc lập chỉ có một artifact. Giữ raw evidence bên C1 và tham chiếu bổ sung
trong receipt. Adapter này kiểm tra tính nhất quán receipt, **không xác thực chữ ký
hoặc tự chứng minh lời khai PASS**; dữ liệu chỉ nhận từ runner/reviewer tin cậy.

```bash
python3 dataset/v2/manage.py export \
  --build dataset/v2/build/controls-r01 --evidence /path/to/c1-receipts \
  --output dataset/v2/releases/controls-r01
python3 -m pipeline.detectors run dataset/v2/releases/controls-r01 \
  --campaign controls-v2-r01
```

Export yêu cầu mọi control trong build đều đạt gate, không âm thầm bỏ mẫu lỗi.
Manifest build vẫn `benchmark_ready=false`; chỉ release được chuyển thành true.
Detector đọc thư mục sẽ bỏ mẫu false, manifest tối giản cũ vẫn dùng được.
Quét EXE trực tiếp dành cho chẩn đoán vẫn được, không đồng nghĩa đủ chuẩn thesis.

## Thực nghiệm và bước tiếp

1. Khôi phục Docker daemon, build hai lần và đối chiếu hash.
2. Tích hợp runner C1 của nhóm, xác minh ba lượt độc lập cho mỗi control.
3. Review cơ chế và contract tám seed; chưa đủ evidence thì giữ pending.
4. Chạy detector đủ năm engine trên release, giữ raw evidence và lỗi hạ tầng.
5. Chỉ sau pilot đạt chuẩn mới mở rộng tới 20 development + 10 held-out.

Control, compiler profile và support variant không được dùng để bù số seed.
Clone/biến thể cùng nguồn gốc giữ cùng split. Mẫu cũ đã dùng phát triển không
đổi nhãn thành held-out. Không chọn mẫu dựa vào việc detector có/không báo alert.
Ngưỡng detector giữ nguyên; báo cáo detection trên fixture tổng hợp, không tự gọi
là TPR trên malware thật hoặc kết luận bypass khi C1 chưa xác nhận.

```bash
python3 -m unittest pipeline.tests.test_dataset_v2
```
