#!/bin/bash
# =============================================================================
# Inject Benign Traffic — Chạy trên máy attacker hoặc máy khác
# Mục tiêu: Tạo traffic bình thường để đo False Positive Rate
# Ngày tạo: 2026-06-06
# =============================================================================

TARGET="${1:-172.16.1.2}"

echo "[$(date '+%H:%M:%S')] Injecting benign traffic → $TARGET"
echo "  Mục đích: Đo False Positive Rate (traffic bình thường KHÔNG bị block)"

# 1. HTTP GET bình thường (truy cập Juice Shop)
echo "  → 30 HTTP GET requests (trang chủ + search)..."
for i in $(seq 1 30); do
    # Truy cập trang chủ
    curl -sk -o /dev/null "https://$TARGET/" &
    # Search từ khóa bình thường
    curl -sk -o /dev/null "https://$TARGET/rest/products/search?q=banana" &
    curl -sk -o /dev/null "https://$TARGET/rest/products/search?q=juice" &
    # Nghỉ 1-2s giữa mỗi batch (giống user thật)
    if (( i % 5 == 0 )); then
        wait
        sleep 1
    fi
done
wait

# 2. Ping bình thường
echo "  → 20 ICMP ping..."
ping -c 20 -i 1 "$TARGET" > /dev/null 2>&1 &

# 3. SSH connection bình thường (nếu có key)
echo "  → 5 SSH connection attempts (bình thường)..."
for i in $(seq 1 5); do
    ssh -o ConnectTimeout=2 -o BatchMode=yes "dmtien@$TARGET" "uptime" 2>/dev/null &
    sleep 2
done
wait

# 4. DNS lookup
echo "  → DNS lookups..."
for i in $(seq 1 10); do
    nslookup "$TARGET" > /dev/null 2>&1 &
done
wait

echo "[$(date '+%H:%M:%S')] Benign traffic injection hoàn tất."
echo "  90 HTTP + 20 ping + 5 SSH + 10 DNS = ~125 benign flows"
echo "  Kỳ vọng: 0 flows bị block (FPR = 0%)"
