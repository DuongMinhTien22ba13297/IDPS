# Kết quả monitor-only: Slow Headers và Slow Body

Ngày kiểm tra: 2026-09-10. Máy IDPS: Ubuntu `192.168.226.151`; nguồn traffic:
`172.16.1.10`; đích: `172.16.1.2:3001`. Model được giữ nguyên ở experiment
`20260908_botnet_excluded_v1`, schema 21 features và ngưỡng production 0.85.

## Phạm vi và trạng thái

- `slow_headers_r1` khởi động lúc 02:48:05 UTC, monitor-only.
- `slow_body_r1` khởi động lúc 03:00:19 UTC, monitor-only.
- Container `autodefense` đang chạy với `MONITOR_ONLY_MODE=true`,
  `SURICATA_ONLY_MODE=false`, `TEST_RUN_ID=slow_body_r1` và không restart lỗi.
- `action_audit.log` không có dòng cho hai run; mọi record đều có
  `enforcement_applied=false`. Không có firewall/blacklist write từ hai run.
- Không tìm thấy PCAP mới cho hai run trong `/home/dmtien`; chỉ có PCAP CICIDS2017
  cũ `/home/dmtien/suricata/Friday-WorkingHours.pcap`. Script
  `tests/start_monitor_run.sh` chỉ đổi mode/run ID và recreate container, không chạy
  `tcpdump`.
- Snapshot raw đã được lưu lúc 03:40:59 UTC tại
  `/home/dmtien/IDPS/experiments/20260910_slow_http_live/`, gồm ML JSONL, EVE liên
  quan, `docker inspect`, summary và SHA-256 manifest. `sha256sum -c` xác minh tất
  cả artifact `OK`.

## Kết quả ML quan sát được

Chỉ thống kê flow có đúng chiều `172.16.1.10 -> 172.16.1.2:3001`. Số liệu
`slow_body_r1` là snapshot đến 03:36:52 UTC vì NFStream còn phát kết quả trễ.

| Run | ML records | Source ports duy nhất | Quyết định | Median/max ML score | Median/max P(DoS-DDoS) | Same-flow Suricata alerts |
|---|---:|---:|---|---:|---:|---:|
| `slow_headers_r1` | 21 | 21 | 21 BENIGN | 0.000655 / 0.000751 | 0.0002 / 0.0002 | 0 |
| `slow_body_r1` | 120 | 93 | 120 BENIGN | 0.000284 / 0.003081 | 0.0000 / 0.0017 | 0 |

Kết luận trực tiếp: trong hai run sạch này không có nhầm lớp Brute Force. Mọi flow
đã được ML chấm đều là false negative ở mức flow nếu ground truth của flow đó được
xác nhận là attack socket. Do chưa có PCAP và log SlowHTTPTest để loại probe/socket
không thành công, chưa dùng các số đếm trên làm recall chính thức.

## Đối chiếu EVE của Suricata

Suricata ghi 113 flow ngoài trên port 3001 cho mỗi cửa sổ, đều `closed` với reason
`timeout`. Median duration lần lượt là 26.352 s (headers) và 27.854 s (body).
Mỗi run có 24 HTTP transactions hoàn chỉnh, đều là `GET`: `/` ở run headers và
`/rest/user/login` ở run body; không có alert.

Các GET của run body không chứng minh cờ `-t POST` bị bỏ qua. SlowHTTPTest duy trì
một probe socket gửi request GET hoàn chỉnh định kỳ, còn request tấn công Slow POST
cố ý để body chưa hoàn chỉnh nên có thể không sinh HTTP transaction hoàn chỉnh trong
EVE. Cần PCAP và log công cụ để gán flow probe/attack chính xác.

Tài liệu tác giả: <https://github.com/shekyan/slowhttptest/wiki/InstallationAndUsage>.

## Lệch phân phối 21 features

So sánh median live với toàn bộ lớp gốc tương ứng trong dataset NFStream cho thấy
traffic lab không giống dấu vết mà model học:

| Feature | Live headers | CICIDS `DoS slowloris` | Live body | CICIDS `DoS Slowhttptest` |
|---|---:|---:|---:|---:|
| `Init_Win_bytes_forward` | 64240 | 229 | 64240 | 29200 |
| `Total Fwd Packets` | 9 | 1 | 9 | 1 |
| `Total Backward Packets` | 8 | 1 | 8 | 0 |
| `PSH Flag Count` | 7 | 1 | 7 | 0 |
| `ACK Flag Count` | 16 | 2 | 16 | 0 |
| `Max Packet Length` | 390 | 297 | 523 | 74 |
| `Total Length of Bwd Packets` | 536 | 66 | 536 | 0 |

Điều này phù hợp với kết quả `P(BENIGN)` gần 1.0. Nguyên nhân có tính hệ thống:
OS/TCP stack, Nginx/Juice Shop và cách đóng socket trong lab khác Apache/Ubuntu và
attack sessions của CICIDS2017. Không được sửa thủ công feature hoặc hạ threshold để
làm score tăng.

## Độ trễ flow nghiêm trọng

- `slow_headers_r1`: decision xuất hiện sau `flow_last_seen_ms` từ 2.366 đến
  15.027 giây, median 2.554 giây.
- `slow_body_r1`: từ 0.699 đến 1,965.470 giây, median 35.400 giây. Các flow có
  packet cuối khoảng 03:01 UTC vẫn được phát theo batch lúc 03:33 UTC.

Đây là độ trễ xuất flow/processing, không phải inference time của XGBoost. Runtime
hiện chỉ dự đoán sau khi NFStream expire flow. NFStream cũng có báo cáo upstream về
flow live bị queue và emit muộn hơn idle timeout trong một số cấu hình; chưa đủ bằng
chứng để khẳng định cùng root cause. Cần bổ sung `expiration_id`, thời điểm emit và
độ trễ `decision_timestamp - flow_last_seen` vào log trước khi sửa.

Tài liệu NFStream: <https://www.nfstream.org/docs/api>. Báo cáo upstream liên quan:
<https://github.com/nfstream/nfstream/issues/120>.

## Kết luận dùng cho khóa luận

Hai phép thử xác nhận pipeline 21 features chạy và monitor-only không chặn traffic,
nhưng chưa phát hiện được Slow Headers/Slow Body mới ngoài corpus. Đồng thời, run
phát hiện một vấn đề production độc lập: quyết định theo flow có thể đến quá muộn để
bảo vệ real-time. Kết quả nên được trình bày như external live-test failure và giới
hạn của post-expiration per-flow classification, không gộp với accuracy holdout của
CICIDS2017.

Lần lặp kế tiếp cần có PCAP trên `ens33`, log CSV/HTML và stdout của SlowHTTPTest,
baseline benign riêng, cùng thời điểm UTC. Chấm lại PCAP trong container offline sẽ
tách được lỗi model khỏi lỗi live expiration/capture.
