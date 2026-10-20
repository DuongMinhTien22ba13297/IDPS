# Báo Cáo Chi Tiết Script: `src/realtime_extractor.py`

## 1. Thông Tin Chung
- **Tên script**: [realtime_extractor.py](file:///c:/IDPS/src/realtime_extractor.py)
- **Các class chính**: `ConnectionTracker`, `ConnectionRatePlugin`, `TCPWindowPlugin`
- **Mục tiêu**: Định nghĩa bộ công cụ bắt lưu lượng mạng sống (live traffic capture) và trích xuất đặc trưng thời gian thực dựa trên nền tảng thư viện `NFStream`. Đảm bảo ánh xạ chính xác từ các cấu trúc dữ liệu gói tin cấp thấp sang vector 30 đặc trưng mạng tương thích với mô hình Machine Learning.

---

## 2. Chức Năng Chính
`realtime_extractor.py` là xương sống của module thu thập dữ liệu thời gian thực (Data Ingestion) trong hệ thống IDPS:
- **Thu thập dữ liệu mạng sống (Live Capture)**: Thiết lập card mạng hoạt động ở chế độ hỗn tạp (promiscuous mode) thông qua `NFStreamer` để thu nhận toàn bộ các gói tin đi qua interface được chỉ định.
- **Trích xuất thông số nâng cao bằng Plugin**: Bổ sung các thông tin đặc trưng của giao thức TCP và thống kê kết nối mà thư viện NFStream mặc định không hỗ trợ thông qua cơ chế viết Plugin tùy chỉnh (`TCPWindowPlugin`, `ConnectionRatePlugin`).
- **Đo lường mật độ kết nối (Port Connection Rate)**: Theo dõi hành vi quét cổng (Port Scanning) hoặc tấn công từ chối dịch vụ (DoS/DDoS) bằng cách đếm tần suất kết nối của một IP nguồn đến các cổng đích khác nhau trong một khung thời gian trượt.
- **Quy đổi đơn vị và cấu trúc (Feature Alignment)**: Ánh xạ và quy đổi chuẩn xác các đơn vị đo thời gian từ mili-giây (ms) của NFStreamer sang micro-giây (µs) để khớp hoàn toàn với cấu trúc đặc trưng của bộ dữ liệu CIC-IDS-2017 dùng huấn luyện mô hình.
- **Vá lỗi tương thích mạng hệ thống (Monkey patching)**: Sửa lỗi xung đột ID tiến trình bắt gói tin khi triển khai Docker Container dưới chế độ mạng `host` (Host network namespace).

---

## 3. Đầu Vào (Input)
- **Card mạng hệ thống (Interface)**: Lấy tên card mạng từ cấu hình hệ thống (mặc định: `ens33`).
- **Luồng gói tin mạng (Flow objects)**: Các gói tin mạng cấp thấp do card mạng nhận được, được NFStream tự động gom nhóm thành các cấu trúc luồng hai chiều (bidirectional flows).
- **Lịch sử kết nối mạng**: Cache lưu trữ timestamp các kết nối của IP nguồn để tính toán mật độ kết nối.

---

## 4. Đầu Ra (Output)
- **Streamer được cấu hình đầy đủ**: Trả về đối tượng `NFStreamer` đã nạp đầy đủ các plugin tùy chỉnh và cấu hình timeout.
- **Mảng vector đặc trưng mạng**: Trả về một mảng NumPy (`np.ndarray`) kiểu `float64` chứa đúng 30 đặc trưng được sắp xếp theo thứ tự bảng chữ cái A-Z (định nghĩa trong biến `FEATURE_NAMES`).

---

## 5. Cơ Chế Hoạt Động

### 5.1 Các Plugin tùy chỉnh nâng cao

1. **TCPWindowPlugin (Trích xuất kích thước cửa sổ TCP)**:
   Mô hình huấn luyện yêu cầu đặc trưng kích thước cửa sổ TCP ban đầu ở chiều thuận (`Init_Win_bytes_forward`) và chiều nghịch (`Init_Win_bytes_backward`).
   - Hàm `on_init` thiết lập các biến tạm lưu giá trị và cờ đánh dấu gói tin đầu tiên.
   - Hàm `on_update` kiểm tra hướng di chuyển của gói tin (`packet.direction`). Nếu gói tin đi từ nguồn đến đích (direction = 0) và là gói đầu tiên, thuộc tính `init_win_fwd` được gán bằng kích thước IP size của gói tin đó. Tương tự, nếu gói tin đi ngược lại (direction = 1) và giá trị nghịch chưa được gán, `init_win_bwd` được chụp lại.

2. **ConnectionTracker & ConnectionRatePlugin (Đo mật độ kết nối)**:
   Để phát hiện các cuộc tấn công quét cổng (PortScan) hoặc rà quét hệ thống, hệ thống cần biết một IP đang kết nối đến bao nhiêu cổng trong thời gian ngắn.
   - Lớp `ConnectionTracker` duy trì một dictionary lưu trữ timestamp của các kết nối:
     `history = { src_ip: { dst_port: [timestamp1, timestamp2, ...] } }`
   - Mỗi khi có luồng kết nối mới, hàm `add_and_count` sẽ thêm timestamp hiện tại (tính bằng giây) vào danh sách cổng đích tương ứng.
   - Tiến hành lọc loại bỏ các timestamp cũ hơn thời gian cửa sổ trượt (`cutoff = current_time - 10` giây) để giải phóng RAM và chỉ giữ lại các kết nối trong vòng 10 giây gần nhất.
   - Trả về độ dài danh sách (số lượng cổng đích mà IP đó kết nối tới trong 10 giây qua) và ghi nhận vào thuộc tính động `flow.udps.conn_rate`.

### 5.2 Xử lý xung đột Docker Host Network (Monkey Patch)

Khi chạy nhiều container Docker dùng chung chế độ mạng `host: true`, NFStreamer sử dụng thuật toán sinh chỉ số nhóm (fanout group ID) bắt đầu từ 0 để giao tiếp với kernel qua Socket. Điều này gây lỗi tranh chấp socket giữa các tiến trình.
Script giải quyết bằng cách áp dụng Monkey Patch ghi đè thuộc tính `_idx` của streamer bằng một số ngẫu nhiên lớn:
```python
streamer._idx = random.randint(10000, 50000)
```
Điều này đảm bảo mỗi khi khởi động container, daemon sẽ đăng ký một fanout group ID độc nhất vô nhị trên hệ thống.

### 5.3 Quy đổi đặc trưng về chuẩn CIC-IDS-2017

Hàm `extract_features` thực hiện chuyển đổi các trường dữ liệu của NFStream sang 30 đặc trưng toán học. Quy tắc chuyển đổi quan trọng:
- **Đơn vị thời gian**: Nhân toàn bộ các trường thời gian của NFStream (mili-giây) với $1000$ để chuyển sang micro-giây (µs) tương thích với CIC-IDS-2017:
  - `duration_us = flow.bidirectional_duration_ms * 1000.0`
  - `Bwd IAT Min = flow.dst2src_min_piat_ms * 1000.0`
- **Tính toán tốc độ truyền**: Tỷ lệ byte/giây và gói tin/giây được tính toán lại bằng cách sử dụng khoảng thời gian an toàn tối thiểu $1.0$ µs làm mẫu số để phòng ngừa lỗi chia cho 0 (`duration_us_safe = max(duration_us, 1.0)`):
  - `Flow Bytes/s = flow.bidirectional_bytes / duration_us_safe * 1e6`
- **Sắp xếp thứ tự đặc trưng**: Vector 30 chiều được sắp xếp chính xác theo thứ tự bảng chữ cái A-Z của tên đặc trưng để đảm bảo khi đưa vào mô hình XGBoost, các giá trị khớp đúng với các cột mô hình đã học lúc train.
- **Cập nhật phiên bản V2**: Loại bỏ 7 đặc trưng không có nhiều đóng góp và bổ sung 7 đặc trưng mới liên quan đến đếm số lượng cờ TCP (SYN, FIN, RST, PSH count), tổng số gói tin thuận/nghịch và kích thước gói tin thuận tối thiểu để mô hình có thể phát hiện hiệu quả hơn các cuộc tấn công Brute Force, Web Attack và PortScan.
