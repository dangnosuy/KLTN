# Single-Revert VM Pipeline

Pipeline thử nghiệm này giữ nguyên `pipeline/vmrun_pipeline.py`. Với mỗi engine,
VM chỉ revert snapshot ở sample đầu tiên; các sample sau dùng lại phiên VM đang
chạy. Mỗi lượt vẫn copy package riêng, chờ proof/telemetry/alert, dọn process
theo PID lineage, xóa thư mục run và kiểm tra lại EDR.

Nếu cleanup không xác minh được, pipeline không chạy thêm sample nào trên phiên
VM đó. Các job còn lại được ghi `NOT_RUN_CONTAMINATED`; engine kế tiếp vẫn bắt
đầu bằng snapshot riêng của nó.

## Chạy

```bash
set -a; source pipeline/vmrun.env.example; set +a

python3 -m pipeline.single_revert.vmrun_pipeline doctor \
  --campaign single-revert-doctor \
  --engines elastic,wazuh,defender

python3 -m pipeline.single_revert.vmrun_pipeline run dataset/advanced/build/ \
  --campaign single-revert-r01 \
  --engines elastic,wazuh,defender \
  --shuffle-seed 23520146
```

Chỉ dùng chế độ này với các mẫu lab đã biết side effect. Cleanup hiện bảo đảm
process lineage, executable trong thư mục run, artifact của run và EDR health;
nó không chứng minh đã hoàn tác driver, kernel modification hay persistence
không khai báo.
