# Đối chiếu kết quả live: DoS, Brute Force và Suricata

Ngày kiểm tra: 2026-09-09 UTC+7. Chỉ đọc VM và chạy phép thử correlation bằng dữ liệu tổng hợp trong bộ nhớ local. Không sửa source/model/rules/dashboard/firewall, không phát traffic và không restart container.

## Kết luận

Có bằng chứng ML phát hiện một số lượt PortScan và FTP Brute Force. Trong snapshot kể từ 20:00 UTC ngày 08/09 (03:00 ngày 09/09 UTC+7), 815 flow nguồn 172.16.1.10, đích port 3001 được ghi ml_probs đều có BENIGN là lớp multiclass cao nhất. Chưa xác nhận DoS được gán Brute Force ở port này; cần thời gian chạy, log công cụ hoặc ảnh màn hình để đối chiếu quan sát đó.

Không dùng 815 flow này làm mẫu số recall của DoS: chúng gồm nhiều ca HTTP, có thể chứa probe hợp lệ, và các flow lúc blacklist bị bỏ qua inference.

Source của bốn module runtime cùng hai model trên VM có SHA-256 khớp local. File dashboard được provision trên VM cũng khớp local. Do đó không thấy dấu hiệu dùng nhầm phiên bản các artifact đã kiểm tra.

## 1. Điểm ML khác điểm quyết định hybrid

| Thời điểm UTC 08/09 | Bằng chứng |
|---|---|
| 20:39:45 | FTP port 21: binary=0.194, multi=0.878, corr=0; P(Brute Force)=0.8779; AUTO_BLOCKED. |
| 20:44:31 | FTP port 21: binary=0.194, multi=0.890, corr=0; P(Brute Force)=0.8898. |
| 20:56:27 | Port 443: binary=0.996, multi=0.994, corr=0; P(PortScan)=0.9931. |
| 21:05:10 | Port 3001: binary=0.001, multi=0.000, corr=0.300; bị ép score=0.900 qua SURICATA_OVERRIDE. |
| 21:20:29 | Port 3001: binary và multi làm tròn 0.000; score quyết định=0.900, suri_alerts=12. |

Các ví dụ PortScan/FTP chứng minh có ca phát hiện, không chứng minh recall cao trên toàn bộ traffic. Đặc biệt binary model riêng có thể thấp trong khi multiclass giúp chặn FTP.

Điểm 0.900 ở các dòng Suricata_L7_DROP không phải P(DoS) hoặc P(Web Attack). Code đặt sàn 0.90 khi cờ suricata_action_drop bật. Xem [autodefense_daemon.py](../src/autodefense_daemon.py), phần SURICATA_OVERRIDE.

## 2. Alert của ca trước làm lẫn ca sau

[suricata_correlator.py](../src/suricata_correlator.py) giữ alert 300 giây và chọn cả deque bằng src_ip. Hàm nhận dst_port nhưng không dùng để lọc alert; không đối chiếu flow hiện tại bằng tuple/thời gian. Custom SID trong khoảng 1000000–1999999 hoặc signature có chữ IDPS đều được coi là virtual drop, kể cả alert.action=allowed.

Timeline đã đối chiếu:

- 21:00:34: SQLi phát sinh SID 1000002 và 1000003; mỗi SID ghi trên cả ens33 và br-idps, tổng bốn bản ghi.
- 21:04:36: IP 172.16.1.10 được unblock.
- 21:05:10: một flow port 3001 bị SURICATA_OVERRIDE, mặc dù binary=0.001 và multi=0.000. Alert SQLi cũ vẫn còn trong cửa sổ 300 giây; không có alert mới giữa hai mốc này trong đoạn EVE đã đọc.

Từ 20:00 UTC tới snapshot, 24 alert EVE liên quan IP test đều là hai SID SQLi trên; chúng đại diện sáu thời điểm request, mỗi thời điểm có hai SID ở hai interface. Chưa có alert SlowHTTP trong tập này. Vì thế chưa thể gọi lần chặn Slow headers là phát hiện SlowHTTP bằng signature.

Phép tái lập local không có mạng: tạo một alert SQLi action=allowed, 90 giây trước, port 443; correlate với flow BENIGN port 3001. Kết quả correlation=0.18 nhưng suricata_action_drop=true. Code daemon sẽ đặt sàn quyết định 0.90 cho trường hợp này. Đây là hành vi correlation theo IP đã tái lập, không phải bằng chứng packet live cụ thể đó chứa SQLi.

Các alert.action quan sát là allowed; log daemon cho thấy autodefense gọi firewall block. Không nên mô tả đơn giản là Suricata trực tiếp drop request web. Theo [Suricata EVE Action/Verdict](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html#action-field), riêng allowed cũng không luôn quyết định verdict cuối của packet; cần phân biệt alert, verdict và hành động firewall của daemon.

## 3. Slow body và cách đọc dashboard

Trong 815 bản ghi port 3001, P(Brute Force) cao nhất quan sát trong log đã làm tròn chỉ là 0.0001. Không có argmax Brute Force. Cấu hình [dashboard](../docker/grafana/provisioning/dashboards/json/idps_dashboard.json) lấy max_over_time theo src_ip cho từng xác suất, không lọc dst_port/run_id. Nó có thể gom FTP, web và DoS trong cùng khoảng quan sát; các cực đại từng lớp không nhất thiết thuộc cùng một flow. Đây là giải thích cần kiểm tra với panel/thời gian người dùng đang xem, không khẳng định màn hình thực tế đã được đọc.

EVE HTTP trên ens33 trong cửa sổ có 369 POST tới đường dẫn chứa /rest/user/login trả 400, cùng 54 GET tới đường dẫn đó trả 500. Các bản ghi tương ứng còn xuất hiện trên br-idps; không cộng hai interface thành gấp đôi số request thực tế. Đây là phản hồi lỗi cần đối chiếu log SlowHTTPTest; chưa xác định riêng các probe/attack flow chỉ từ tổng số này.

SlowHTTPTest có tạo request probe hoàn chỉnh ngoài các kết nối gửi chậm. Một probe hợp lệ bị ML gán BENIGN không tự là false negative. [Tài liệu tác giả](https://github.com/shekyan/slowhttptest/wiki/InstallationAndUsage).

Model hiện không có URL, phương thức HTTP, payload hoặc số authentication failure trong 21 đầu vào. Vì thế không được giải thích nhãn Brute Force là do model nhìn thấy /rest/user/login. Nếu sau này xác nhận nhầm lớp trên một flow DoS, cần phân tích vector thống kê của chính flow đó.

## 4. Việc nên làm tiếp, chưa triển khai

1. Sửa protocol đo trước khi retrain: tách raw ML, hybrid, nguồn rule/SID, hành động firewall, flow/run_id; debug panel phải lọc được port và phiên kiểm thử.
2. Thiết kế monitor-only thực sự cho lab: vẫn capture, chấm điểm và ghi log, nhưng không block hoặc bỏ qua inference vì blacklist. Không dùng whitelist hay SURICATA_ONLY_MODE làm thay thế. Không tự tắt bảo vệ production.
3. Tách tương quan cùng flow khỏi risk theo IP: đối chiếu tuple/time, xử lý NAT/proxy khi cần; giữ lịch sử theo IP thành một tín hiệu riêng, không gán alert SQLi cũ là bằng chứng SlowHTTP mới. Không coi NFStream flow.id và Suricata flow_id là cùng namespace.
4. Khử trùng alert do capture hai interface trước khi tính repeat-offender; ghi riêng virtual policy block và Suricata packet drop thật.
5. Trong khi chưa sửa: dừng mọi generator, đợi hơn 5 phút kể từ alert cuối cùng (ví dụ 6 phút), xác minh IP đã unblock và kết nối cũ kết thúc trước ca mới. Chờ TTL 60 giây đơn thuần chưa đủ. Không xóa log hoặc restart dịch vụ chỉ để làm sạch phép đo.
6. Đo Slow headers/Slow body với PCAP, log công cụ và tình trạng socket/server, rồi chấm thụ động bằng extractor hiện tại. Tách traffic tấn công và probe; không gọi toàn bộ POST lỗi 400 là brute force.
7. Sau khi có ca độc lập vẫn bị bỏ sót, phân tích riêng các subtype DoS, kiểm tra ablation đặc trưng phụ thuộc môi trường, cân nhắc dữ liệu lab nhiều môi trường và đặc trưng tổng hợp nhiều flow. Chọn thay đổi bằng validation; không hạ threshold hay sửa TCP window để làm đẹp ca test.

Chi tiết máy đọc được: [dos_live_followup_evidence_20260909.json](dos_live_followup_evidence_20260909.json). Các kết luận về chính xác thời điểm Slow headers/Slow body vẫn cần log/timestamp của người chạy.
