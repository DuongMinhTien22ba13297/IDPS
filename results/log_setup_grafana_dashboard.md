# Báo cáo Thiết lập Dashboard Grafana Monitoring (Real-time Flow Extraction)

Hệ thống đã được cấu hình để tự động hóa việc giám sát các luồng traffic (flows) được trích xuất từ NFStreamer thông qua ngăn xếp Grafana Loki.

---

## 1. Tích hợp Đẩy Log từ Autodefense Daemon (Loki Integration)

Để Grafana có thể hiển thị dữ liệu, tệp `src/autodefense_daemon.py` đã được cập nhật để tích hợp `LokiHandler`.

**Các thay đổi chính:**
- Thêm thư viện `logging_loki`.
- Cấu hình đẩy log về URL: `http://localhost:3100/loki/api/v1/push`.
- Gắn nhãn (tags) động cho mỗi flow: `src_ip`, `dst_ip`, `dst_port`, `protocol`.

---

## 2. Cấu hình Hạ tầng Grafana Provisioning

Sử dụng cơ chế Provisioning để tự động thiết lập mà không cần thao tác tay trên giao diện web.

### A. Cấu hình Nguồn dữ liệu (Data Source)
Tệp `docker/grafana/provisioning/datasources/loki.yml`:
```yaml
apiVersion: 1
datasources:
  - name: Loki
    uid: loki_ds
    type: loki
    url: http://loki:3100
    access: proxy
    isDefault: true
```

### B. Cấu hình Nạp Dashboard (Provider)
Tệp `docker/grafana/provisioning/dashboards/provider.yml`:
```yaml
apiVersion: 1
providers:
  - name: 'IDPS Dashboards'
    options:
      path: /etc/grafana/provisioning/dashboards/json
```

### C. Giao diện Dashboard (Dashboard JSON)
Đã tạo tệp `idps_dashboard.json` với 3 biểu đồ chính:
1. **Flow Rate:** Tốc độ lưu lượng theo thời gian.
2. **Live Flow Logs:** Chi tiết các luồng đang hoạt động.
3. **Top Destination Ports:** Phân tích các dịch vụ đang được truy cập.

---

## 3. Nhật ký Khắc phục sự cố (Troubleshooting Log)

Trong quá trình triển khai trên Ubuntu VM, đã phát hiện và xử lý các lỗi sau:

### Lỗi 1: Connection Refused (Grafana Crash Loop)
**Nguyên nhân:** Tệp YAML bị lẫn ký tự xuống dòng của Windows (`\r\n`) khi upload qua SSH, khiến Grafana không thể khởi động.
**Command xử lý:**
```bash
# Loại bỏ ký tự \r ẩn
ssh dmtien@192.168.226.151 "find IDPS/docker/grafana/provisioning -type f -exec sed -i 's/\r$//' {} +"

# Xóa cơ sở dữ liệu cũ bị lỗi để khởi động sạch
ssh dmtien@192.168.226.151 "docker run --rm -v /home/dmtien/IDPS/docker/grafana/data:/data alpine sh -c 'rm -rf /data/*'"
```

### Lỗi 2: Dashboard không hiện dữ liệu (Empty Charts)
**Nguyên nhân:** Query LogQL sử dụng `| json` trong khi log được gửi dưới dạng nhãn (labels). Ngoài ra, UID của Data Source không khớp.
**Command fix Query:**
Sửa `sum by (dst_port) (count_over_time({application="idps-autodefense"} | json [1h]))` 
Thành `sum by (dst_port) (count_over_time({application="idps-autodefense"} [1h]))`

---

## 4. Lệnh Quản trị & Kiểm tra

**Khởi động lại hệ thống trên VM:**
```bash
cd IDPS/docker
docker compose up -d --force-recreate
```

**Kiểm tra Log hoạt động:**
```bash
# Xem log của container Autodefense trích xuất flow
docker compose logs -f autodefense

# Log mẫu:
# autodefense  | 2026-04-26 01:06:30,759 [INFO] Flow 9 captured
# autodefense  | 2026-04-26 01:06:31,102 [INFO] Đã kết nối với Loki thành công.
```

**Kiểm tra dữ liệu trong Loki:**
```bash
curl -s http://localhost:3100/loki/api/v1/labels
# Kết quả mong đợi: ["application", "src_ip", "dst_port", ...]
```

---

## 5. Kết quả Cuối cùng
- **Địa chỉ truy cập:** `http://192.168.226.151:3000` (User: `admin` / Pass: `admin`).
- **Trạng thái:** Toàn bộ flows từ máy ảo đã được đẩy về dashboard theo thời gian thực (độ trễ ~10 giây do `idle_timeout`).
