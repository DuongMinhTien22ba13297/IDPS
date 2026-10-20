# Chẩn đoán điểm tấn công thấp sau triển khai 21 features

Ngày chẩn đoán: 2026-09-09, giờ Việt Nam/Thái Lan (UTC+7).
VM: `192.168.226.151`; IP phát traffic được quan sát: `172.16.1.10`.
Cửa sổ log chính: 2026-09-08 19:33–19:53 UTC (2026-09-09 02:33–02:53 UTC+7).

## Kết luận

Điểm thấp có thật trong đầu ra mô hình. Source/model trên VM có SHA-256 khớp
bản 21 features đã triển khai. Tính lại trên máy local bốn vector lấy nguyên
từ log VM cho kết quả khớp các score trong log sau làm tròn.
Không thấy bằng chứng sai thứ tự features hoặc dùng nhầm model trong lượt kiểm tra này.

Hai vấn đề đã xác nhận: mô hình phụ thuộc vào đặc điểm dữ liệu huấn luyện
không đại diện đủ cho lab hiện tại, và nhánh Suricata thiếu rule cho các hành
vi đang thử. Nmap còn thiếu log tương ứng để kết luận nguyên nhân của chính lượt chạy.

Kiểm thử ngày 08/09 trước đó chỉ xác minh capture, inference, decision, logging
và TTL trên traffic tổng hợp. Nó chưa chứng minh recall của ba kịch bản live;
không được dùng kết quả smoke test để khẳng định khả năng phát hiện thực tế.

## Bằng chứng theo kịch bản

| Kịch bản | Quan sát trên VM |
|---|---|
| Hydra FTP | 28 flow port 21 bị gán BENIGN; score min/median/max = 0.004/0.036/0.051. EVE có 76 giao dịch PASS trả mã 530, chứng minh có các lần đăng nhập thất bại thực tế. |
| SlowHTTP | 1.340 quyết định BENIGN trên port 80; median score trong nhóm này = 0.001, max = 0.548. Thêm một quyết định SUSPICIOUS score 0.645, corr=0.000; không có AUTO_BLOCK từ IP test trong log container. |
| Nmap | Chưa tìm được quyết định port 22/443/3000/3001/8080 của IP 172.16.1.10 trong log container hiện tại và file autodefense.log từ ngày 08/09. Không suy ra recall cho lượt Nmap từ dữ liệu hiện có. |

Các số đếm trên là quan sát log, không phải metric recall đã được gán nhãn và
đối chiếu từng flow theo protocol độc lập.

## 1. Dấu vết dữ liệu huấn luyện trong quyết định mô hình

So sánh trên toàn bộ 1.320.394 dòng development của experiment đã khóa:

- Toàn bộ 5.106 dòng Brute Force có `Init_Win_bytes_forward=29200`.
- Những flow FTP live kiểm tra có TCP window `64240`.
- Lớp PortScan trong development chủ yếu có window `29200` (68.892 dòng)
  hoặc `1024` (58.693 dòng); chỉ một dòng có window `64240`.
- Các quantile 5%/50%/95% của `Bwd Packets/s` trong lớp PortScan đều là `1000`.
  Điều này mô tả các flow riêng lẻ rất ngắn của corpus; không phải tốc độ quét
  nhiều cổng của cả chiến dịch.
- Nhóm DoS/DDoS gộp nhiều kiểu tấn công. Median Max Packet Length = 5858 trong
  development; hai vector HTTP live đại diện có max = 297. Không được coi
  median nhóm DoS/DDoS này là phân bố riêng của Slowloris.

Phân tích đóng góp cây XGBoost (raw-margin, không phải phần trăm xác suất) cho
bốn vector live cho thấy TCP window `64240` đều đẩy quyết định về BENIGN so với
lớp Brute Force hoặc DoS/DDoS. Các đặc trưng Down/Up Ratio, PSH và kích thước
gói cũng tác động; TCP window không phải nguyên nhân duy nhất.

Ví dụ FTP flow 1676: binary=0.050784, P(Brute Force)=0.007279,
P(BENIGN)=0.991386. Tính lại từ vector log tái hiện score=0.051.
Chi tiết và script tái lập: `training_comparison.json`,
`compare_live_training.py`.

Đây là bằng chứng mô hình học cả dấu vết môi trường/cách tạo traffic.
Không thay giá trị TCP window live bằng giá trị training để nâng score.

## 2. Bộ rule Suricata thiếu và correlation chưa có tín hiệu

Startup log:

```text
No rule files match the pattern /var/lib/suricata/rules/suricata.rules
12 rules successfully loaded
```

12 rule đang nạp tập trung vào SQLi, XSS, command injection, traversal, DNS,
download và SSH brute force. Không có rule FTP brute force, SlowHTTP hoặc
quét nhiều cổng trong bộ custom đang chạy. Rule SSH trên port 22 không áp dụng
cho lệnh Hydra dùng FTP port 21.

EVE ghi flow/http/ftp nhưng không có alert trong cửa sổ log kiểm tra.
Correlator chỉ đọc event_type=alert, nên các giao dịch FTP 530 chưa trở thành
tín hiệu trong decision engine. Khôi phục rule thiếu là việc cần làm, nhưng
không tự thay đổi predict_proba của XGBoost.

HOME_NET hiện bao phủ 172.16.0.0/12, gồm cả Kali 172.16.1.10;
EXTERNAL_NET=!HOME_NET. Khi khôi phục bộ rule, cần kiểm tra hướng và mạng
nguồn của từng rule để traffic lab nội bộ có thể khớp các rule thích hợp.

## 3. SlowHTTP đang gặp endpoint và phiên TCP khác corpus huấn luyện

Port 80 của Nginx cấu hình redirect 301 sang HTTPS; proxy tới Juice Shop nằm
ở port 443. Log Nginx cho nguồn test ghi 2 request 301 và 993 request 400.
EVE trên đích 172.16.1.2 ghi 2 HTTP status 301 và 1.001 transaction không có
status; 1.004 flow HTTP đóng, age min/median/max = 0/28/35 giây.

Do đó không thể nói toàn bộ 400 trong access log là HTTP response đã gửi
ra mạng: nhiều transaction không có response trong EVE. Cũng không thể kết
luận phép thử vô hại chỉ vì có redirect hoặc score thấp. Cần log phía
slowhttptest để xác định số kết nối giữ được, thời lượng và tình trạng dịch vụ.

## 4. Thiếu hành vi tổng hợp giữa nhiều flow

21 đầu vào hiện tại đều là thống kê của từng flow. Model không nhận trực tiếp:

- số cổng đích khác nhau đã quét theo IP trong một cửa sổ thời gian;
- số FTP authentication failure (530) theo IP;
- số kết nối HTTP đồng thời và tình trạng header chưa hoàn chỉnh.

`ConnectionRatePlugin` có tính `conn_rate`, nhưng giá trị này không nằm trong
21 features và không được dùng trong `process_flow`.
Vì vậy tên công cụ hoặc cờ `-c 1000` không tự trở thành bằng chứng đầu vào ML.

Nmap -sS tạo các kết nối bắt tay không hoàn chỉnh theo từng cổng. Sáu cổng với
nhịp quét chậm cần được đánh giá cả bằng thống kê nhiều flow. Đây là giới hạn
kiến trúc đã thấy trong code, chưa phải kết luận về packet của lượt Nmap chưa có log.

## Hướng xử lý theo thứ tự

1. Hoàn thiện bộ quan sát/luật hành vi của lab: FTP 530, nhiều cổng khác nhau,
   HTTP nhiều kết nối chưa hoàn chỉnh; xác minh Suricata nạp đúng rule và HOME_NET.
2. Lưu score ML và quyết định từ rule/hành vi thành các trường riêng; kiểm thử
   từng trường hợp và traffic hợp lệ để đo false positive. Không coi điểm
   fusion cộng heuristic là xác suất đã hiệu chỉnh.
3. Thu PCAP và nhãn từ lab cho từng kịch bản cùng traffic benign; đối chiếu
   feature extraction trên cùng PCAP giữa offline/runtime, rồi đánh giá ngoài corpus.
4. Làm ablation TCP window và các đặc trưng phụ thuộc môi trường; huấn luyện
   với dữ liệu đa môi trường hoặc feature hành vi có pipeline tương ứng.
   Chọn threshold trên validation và đo lại false positive, không hạ threshold
   chỉ để ba lệnh thử được chặn.
5. Bổ sung thời điểm/IP/output của Nmap để hoàn tất đối chiếu lượt quét.

Lượt này chỉ đọc trạng thái VM và tạo các tệp chẩn đoán mới tại local;
không chỉnh model, threshold, firewall, cấu hình hay khởi động lại dịch vụ.

## Nguồn kỹ thuật

- NFStream API (flow, timeout, accounting mode): https://www.nfstream.org/docs/api
- SlowHTTPTest: https://github.com/shekyan/slowhttptest/wiki
- Nmap SYN scan: https://nmap.org/book/man-port-scanning-techniques.html
- Quản lý rules Suricata: https://docs.suricata.io/en/suricata-8.0.1/rule-management/suricata-update.html
- Probability calibration: https://scikit-learn.org/stable/modules/calibration.html
