# Log: Thay thế Elasticsearch/Kibana bằng Loki/Grafana và Kiểm tra Feature Extraction

**Thời gian:** 2026-04-26
**Mục tiêu:** 
1. Thay thế stack giám sát Elasticsearch + Kibana bằng Loki + Grafana.
2. Cập nhật cấu hình Docker và dependencies.
3. Triển khai Autodefense Daemon để kiểm tra việc trích xuất 30 features từ NFStream.

---

## 1. Cập nhật cấu hình Docker (PLG Stack)

### Thay đổi Docker Compose
Đã cập nhật `docker-compose.yml` để gỡ bỏ Elasticsearch/Kibana và thêm Loki/Grafana.

**Command:**
```bash
ssh dmtien@192.168.226.151 "docker compose down"
ssh dmtien@192.168.226.151 "rm -rf /home/dmtien/IDPS/docker/elasticsearch"
```

**File `docker-compose.yml` mới:**
```yaml
services:
  suricata: ...
  autodefense:
    depends_on:
      - loki
  loki:
    image: grafana/loki:latest
    container_name: loki
    ports: ["3100:3100"]
    volumes: ["./loki/data:/loki"]
  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports: ["3000:3000"]
    depends_on: ["loki"]
```

### Cập nhật Dependencies
Thay thế `elasticsearch` bằng `python-logging-loki` trong `requirements.txt`.

---

## 2. Triển khai Autodefense Daemon & Realtime Extractor

Đã upload các file mã nguồn vào thư mục `src/` trên VM để container `autodefense` sử dụng.

**Commands:**
```bash
scp f:\IDPS\src\autodefense_daemon.py dmtien@192.168.226.151:/home/dmtien/IDPS/src/autodefense_daemon.py
scp f:\IDPS\src\realtime_extractor.py dmtien@192.168.226.151:/home/dmtien/IDPS/src/realtime_extractor.py
ssh dmtien@192.168.226.151 "docker compose up -d --build"
```

---

## 3. Kiểm tra trích xuất 30 Features

### Thực thi công cụ kiểm tra (Check-tool)
Đã chạy script `check_features.py` bên trong container để verify việc trích xuất đặc trưng từ traffic thực tế.

**Command:**
```bash
ssh dmtien@192.168.226.151 "docker exec autodefense python3 /app/src/check_features.py"
```

**Log Output (Success):**
```text
Bắt đầu sniff với idle_timeout=1s để lấy kết quả nhanh...
Đang chờ traffic (Hãy thử curl hoặc ping trên VM)...

[+] Đã bắt được flow: 192.168.226.151-142.251.218.164-62193-80-6
[+] Số lượng features trích xuất: 30
[OK] Trích xuất ĐỦ 30 features!

Chi tiết 30 features trích xuất được:
  1. Idle Max                       : 0.0
  2. Idle Mean                      : 0.0
  3. Flow Duration                  : 0.002
  4. Idle Min                       : 0.0
  5. Fwd IAT Min                    : 2.0
  ...
 29. Packet Length Mean             : 58.0
 30. Bwd Packet Length Mean         : 62.0
```

---

## 4. Trạng thái hệ thống hiện tại

| Container | Status | Port |
|-----------|--------|------|
| suricata  | Up     | Host |
| autodefense| Up     | Host |
| loki      | Up     | 3100 |
| grafana   | Up     | 3000 |

Hệ thống đã sẵn sàng cho việc đẩy log từ Python sang Loki và hiển thị trên Dashboard Grafana.
