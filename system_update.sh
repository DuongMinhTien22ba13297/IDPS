#!/bin/bash

# 1. Sửa nội dung file blacklist.json
JSON_FILE="/home/dmtien/IDPS/configs/blacklist.json"

cat <<EOF > "$JSON_FILE"
{
    "description": "IP Blacklist - Auto-blocked by IDPS ML detection + manual entries",
    "ips": []
}
EOF

echo "Đã cập nhật nội dung file $JSON_FILE"

# 2. Xóa luật INPUT đầu tiên trong iptables
# Sử dụng sudo vì thao tác với iptables yêu cầu quyền root
if sudo iptables -D INPUT 1 2>/dev/null; then
    echo "Đã xóa luật (rule) đầu tiên trong chuỗi INPUT của iptables"
else
    echo "Không có luật nào trong chuỗi INPUT để xóa (iptables đang trống)"
fi

# 3. Làm mới dữ liệu Loki
LOKI_DATA_DIR="/home/dmtien/IDPS/docker/logs/loki-data"
echo "Đang làm mới dữ liệu Loki tại $LOKI_DATA_DIR..."
if [ -d "$LOKI_DATA_DIR" ]; then
    sudo rm -rf "$LOKI_DATA_DIR"/*
    echo "Đã xóa dữ liệu cũ của Loki."
else
    echo "Thư mục $LOKI_DATA_DIR không tồn tại, sẽ được Loki tự động tạo khi khởi động."
fi

# 4. Khởi động lại các container
echo "Khởi động lại các container..."
cd /home/dmtien/IDPS/docker && docker compose restart
echo "Đã khởi động lại các container"
