# Triển khai quan sát, monitor-only và correlation theo flow

Ngày triển khai: 2026-09-09. VM: `192.168.226.151`.

## Trạng thái bàn giao

- `autodefense`: running, restart count 0.
- `grafana`: running, restart count 0; dashboard provisioning hoàn tất.
- Chế độ hiện tại: `MONITOR_ONLY_MODE=true`, `SURICATA_ONLY_MODE=false`.
- Run ID hiện tại: `dos_validation_20260909`.
- Model vẫn là experiment `20260908_botnet_excluded_v1`, 21 features, 5 lớp.
- Blacklist trống; không thấy rule INPUT cho `172.16.1.10` sau triển khai.
- Không có `AUTO_BLOCKED` kể từ khi bật monitor-only. Chưa có traffic từ Kali sau thời điểm bật để tạo `WOULD_BLOCK`/`ml_probs` mới.

**Cảnh báo:** monitor-only không ghi firewall hoặc blacklist. Trong khi chế độ này bật, hệ thống quan sát và ghi `WOULD_BLOCK` nhưng không bảo vệ dịch vụ bằng auto-block.

## Ba thay đổi đã thực hiện

### 1. Quan sát và dashboard

Mỗi bản ghi `ml_probs` mới chứa:

- `run_id`, `mode`, NFStream `flow_id`;
- source/destination IP và port, protocol, first/last seen;
- `binary_score`, `multi_attack_score`, `ml_confidence` thô;
- `correlation_score`, `hybrid_confidence`;
- nhãn ML, nhãn hybrid, quyết định và `enforcement_applied`;
- chi tiết SID/signature, alert cùng flow, alert lịch sử và số alert bị khử trùng.

Dashboard có thêm bộ lọc **Test run** và **Destination port**. Panel log hiển thị bản ghi theo flow. Panel xác suất bỏ Botnet/Exploitation đã bị loại khỏi model và dùng giá trị của flow mới nhất trong khoảng chọn thay vì lấy cực đại độc lập của từng lớp.

### 2. Monitor-only thật

`MONITOR_ONLY_MODE=true` vẫn chạy 21-feature extraction, binary model, multiclass model và Suricata correlation. Nó không gọi `block_ip`, không ghi blacklist, không tạo/slide TTL và không chạy unblock scheduler. Whitelist/blacklist không làm skip inference trong chế độ này.

Ngưỡng và model không bị thay đổi. Kết quả vượt ngưỡng được ghi là `WOULD_BLOCK`; `enforcement_applied=false`.

### 3. Correlation theo flow

Correlation không còn lấy mọi alert chỉ theo source IP. Alert phải khớp source port, protocol, cửa sổ thời gian và destination port/port backend đã cấu hình. Mapping hiện dùng `80→3000`, `443→3000`, `3001→3000` cho đường reverse proxy/Docker bridge.

Alert cùng request quan sát ở `ens33` và `br-idps` được khử trùng theo SID, source tuple và time bucket. Alert lịch sử vẫn xuất trong diagnostic fields nhưng không cộng score hoặc override flow mới.

`suricata_packet_drop`, `suricata_policy_match` và `suricata_enforcement_requested` được tách riêng. Custom IDPS alert có `action=allowed` được mô tả là policy match, không còn bị gọi sai là packet drop.

## Kiểm thử

- Local: 13/13 test qua, gồm 8 test runtime 21 features và 5 test mới.
- VM staging: Python compile, JSON parse, Bash syntax, Docker Compose validation đều qua.
- VM: 5/5 test monitor/correlation qua.
- Test xác nhận monitor-only không gọi mock firewall/blacklist.
- Test xác nhận alert cũ cùng IP nhưng khác flow có score 0.
- Test xác nhận hai alert cùng request qua hai interface được gộp thành một.
- Test xác nhận policy match `allowed` và packet action `blocked` là hai trạng thái khác nhau.

## Backup và rollback

Backup local trước thay đổi:

`C:\IDPS\backups\20260909_observability_monitor_correlation_v1`

Backup VM trước thay đổi:

`/home/dmtien/IDPS/backups/20260909_observability_monitor_correlation_v1`

Các file gốc trong backup VM có SHA-256 được ghi khi sao lưu. Không sửa model, dataset, thresholds hoặc Suricata rules trong lượt này.

## Hướng dẫn cho bước 4

Mỗi subtype/lần lặp dùng một run ID khác nhau. Ví dụ trước khi chạy slow headers lần 1:

```bash
cd /home/dmtien/IDPS
bash tests/start_monitor_run.sh slow_headers_r1
```

Sau khi dòng `MONITOR_ONLY_MODE=true` và `TEST_RUN_ID=slow_headers_r1` xuất hiện, bắt PCAP trên Ubuntu rồi mới phát traffic từ Kali:

```bash
PCAP_DIR=$(mktemp -d -p /home/dmtien slow_headers_r1.XXXXXX)
date -u +%Y-%m-%dT%H:%M:%SZ | tee "$PCAP_DIR/start_utc.txt"
sudo timeout --signal=INT --kill-after=5s 300s \
  tcpdump -i ens33 -nn -s 0 -U -w "$PCAP_DIR/traffic.pcap" \
  'host 172.16.1.10 and host 172.16.1.2'
```

Giữ tcpdump chạy khi phát traffic. Sau khi generator dừng, chờ ít nhất 45–60 giây để các flow active/idle được xuất rồi mới kết thúc capture. Lưu thời điểm kết thúc và log daemon:

```bash
date -u +%Y-%m-%dT%H:%M:%SZ | tee "$PCAP_DIR/end_utc.txt"
docker logs --since "$(cat "$PCAP_DIR/start_utc.txt")" autodefense \
  > "$PCAP_DIR/autodefense.log" 2>&1
cp /home/dmtien/IDPS/logs/suricata/eve.json "$PCAP_DIR/eve_snapshot.json"
```

Trên Grafana chọn:

- Source IP: `172.16.1.10`;
- Test run: đúng run ID vừa đặt;
- Destination port: `3001` cho ca plaintext đã đề xuất.

Không chạy đồng thời các subtype. Dùng các run ID như `slow_headers_r1`, `slow_headers_r2`, `slow_body_r1`, `goldeneye_r1`, `benign_http_r1`. Log phải được giữ cùng PCAP; không chỉ chụp panel.

Sau khi hoàn tất toàn bộ bước 4, bật lại bảo vệ:

```bash
cd /home/dmtien/IDPS
bash tests/restore_enforcement.sh
```

Phải xác nhận đầu ra có `MONITOR_ONLY_MODE=false`, `SURICATA_ONLY_MODE=false`, `TEST_RUN_ID=production` trước khi coi hệ thống đã trở lại production.
