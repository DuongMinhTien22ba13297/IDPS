# Báo Cáo Tuần 7

## Zero-Touch IDPS: Monitoring Dashboard

**Thời gian:** 22/05/2026 - 28/05/2026  
**Trạng thái:** ✅ Hoàn thành

---

## Mục lục

1. [Yêu cầu Tuần 7](#1-yêu-cầu-tuần-7)
2. [Cài đặt và kết nối Grafana với Loki](#2-cài-đặt-và-kết-nối-grafana-với-loki)
   - [2.1 Cấu hình Grafana Docker](#21-cấu-hình-grafana-docker)
   - [2.2 Cơ chế Provisioning](#22-cơ-chế-provisioning)
3. [Thiết kế biểu đồ thống kê](#3-thiết-kế-biểu-đồ-thống-kê)
   - [3.1 Các chỉ số được giám sát](#31-các-chỉ-số-được-giám-sát)
   - [3.2 Dashboard JSON](#32-dashboard-json)
4. [Quá trình xử lý sự cố](#4-quá-trình-xử-lý-sự-cố)
5. [Kết quả thực thi](#5-kết-quả-thực-thi)
6. [Ảnh chụp màn hình](#6-ảnh-chụp-màn-hình)

---

## 1. Yêu cầu Tuần 7

| # | Yêu cầu | Trạng thái |
|---|---------|-----------|
| 1 | Install Grafana, connect with Loki | ✅ Hoàn thành |
| 2 | Design statistical charts | ✅ Hoàn thành |

---

## 2. Cài đặt và kết nối Grafana với Loki

### 2.1 Cấu hình Grafana Docker

Grafana được cấu hình chạy song song với Loki thông qua Docker Compose, tạo thành cụm giám sát trung tâm cho toàn bộ hệ thống IDPS.

**Trích xuất cấu hình:**
```yaml
  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - ./grafana/data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning
    networks:
      - idps_net
```

### 2.2 Cơ chế Provisioning

Hệ thống sử dụng cơ chế Provisioning của Grafana để tự động thiết lập nguồn dữ liệu (Data Source) mà không cần cấu hình bằng tay trên giao diện web.

**Tệp `docker/grafana/provisioning/datasources/loki.yml`:**
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
Loki được cấu hình làm Data Source mặc định, lấy dữ liệu từ `http://loki:3100` trong cùng mạng Docker.

---

## 3. Thiết kế biểu đồ thống kê

Hệ thống cung cấp cái nhìn tổng quan về tình trạng mạng theo thời gian thực (Real-time Flow Extraction) thông qua các biểu đồ đa dạng.

### 3.1 Các chỉ số được giám sát

1. **Flow Rate (per minute):**
   - Biểu đồ đường (Time series) hiển thị tốc độ lưu lượng mạng, giúp nhận diện sự bất thường (như DDoS, Scan).
2. **Live Flow Logs:**
   - Bảng log theo thời gian thực hiển thị chi tiết mọi luồng được ghi nhận.
3. **Top Source IPs:**
   - Biểu đồ xếp hạng các địa chỉ IP nguồn tạo ra nhiều kết nối nhất hoặc có hành vi đáng ngờ nhất.
4. **Threat Logs (Non-Benign):**
   - Bảng tổng hợp chuyên biệt lọc các sự kiện có nguy cơ, hiển thị loại tấn công dự đoán, điểm xác suất (confidence score) và hành động hệ thống (như AUTO_BLOCKED).
5. **ML Multi-Class Probabilities:**
   - Biểu đồ phân tích JSON bóc tách chi tiết xác suất của từng phân loại tấn công từ mô hình Machine Learning.

### 3.2 Dashboard JSON

Dashboard được định nghĩa dưới dạng JSON và nạp tự động qua provider của Grafana:
**Tệp `docker/grafana/provisioning/dashboards/provider.yml`:**
```yaml
apiVersion: 1
providers:
  - name: 'IDPS Dashboards'
    options:
      path: /etc/grafana/provisioning/dashboards/json
```

---

## 4. Quá trình xử lý sự cố

Trong quá trình triển khai, đã xuất hiện và xử lý một số lỗi sau để đảm bảo hoạt động ổn định:

1. **Connection Refused (Grafana Crash Loop):**
   - *Nguyên nhân:* Tệp YAML bị lẫn ký tự xuống dòng của Windows (`\r\n`) khi chuyển lên VM Ubuntu.
   - *Khắc phục:* Sử dụng lệnh `sed -i 's/\r$//'` để chuẩn hóa lại định dạng Unix và khởi động lại volume `/var/lib/grafana`.
2. **Dashboard hiển thị rỗng (Empty Charts):**
   - *Nguyên nhân:* Câu lệnh LogQL sử dụng bộ lọc `| json` không cần thiết do log đã được chuẩn hóa qua labels.
   - *Khắc phục:* Sửa câu lệnh từ `count_over_time({application="idps-autodefense"} | json [1h])` thành `count_over_time({application="idps-autodefense"} [1h])`.

---

## 5. Kết quả thực thi

### 5.1 Kiểm tra trạng thái dịch vụ

```bash
docker ps | grep grafana
```
**Kết quả mong đợi:** Cả hai container `loki` và `grafana` chạy ổn định trên cổng 3100 và 3000.

### 5.2 Kiểm tra kết nối Data Source

```bash
curl -s http://localhost:3100/loki/api/v1/labels
```
Grafana gọi API này và lấy được các nhãn như `application`, `src_ip`, `dst_port` thành công.

---

## 6. Ảnh chụp màn hình

### 6.1 Giao diện Grafana Dashboard

> **[CHÈN ẢNH CHỤP MÀN HÌNH TẠI ĐÂY]**
> 
> Ảnh minh họa: Màn hình Dashboard Grafana với các biểu đồ thống kê Real-time Flow, danh sách IP bị block, và tỷ lệ truy cập các Port (Top Destination Ports).

---

### 6.2 Data Source Settings (Loki connection)

> **[CHÈN ẢNH CHỤP MÀN HÌNH TẠI ĐÂY]**
> 
> Ảnh minh họa: Hình ảnh phần Settings > Data sources trên Grafana xác nhận Loki (URL: `http://loki:3100`) báo "Data source is working".

---

## 7. Tóm tắt

Tuần 7 đã hoàn thiện mảnh ghép cuối cùng của hệ thống giám sát:

1. **Cài đặt Grafana**: Triển khai Grafana và tự động hóa kết nối (Provisioning) với backend Loki thành công. Các lỗi phát sinh liên quan đến môi trường VM cũng được giải quyết triệt để.
2. **Thiết kế Biểu đồ**: Đã xây dựng Dashboard phản ánh các sự kiện bảo mật trực quan, bao gồm tốc độ truy cập, cổng đích bị tấn công và danh sách IP bị chặn theo thời gian thực (Real-time flow extraction), giúp người quản trị nhanh chóng nhận diện rủi ro mà không cần phân tích log thô.

---

**Báo cáo được tạo:** Tuần 7 (22/05/2026 - 28/05/2026)  
**Trạng thái:** ✅ Hoàn thành
