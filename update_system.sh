#!/bin/bash

# 1. Sửa nội dung file blacklist.json
# Đường dẫn file (Bạn hãy thay đổi /path/to/ cho đúng với vị trí thực tế của file)
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

# 3. Khởi động lại các container
echo "Khởi động lại các container..."
cd /home/dmtien/IDPS/docker && docker compose restart
echo "Đã khởi động lại các container"
