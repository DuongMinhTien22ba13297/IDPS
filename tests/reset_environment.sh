#!/bin/bash
# =============================================================================
# Reset Environment — Chạy trên Server (172.16.1.2)
# Mục tiêu: Reset nhanh giữa các kịch bản test (flush iptables + clear blacklist)
# Ngày tạo: 2026-06-06
# =============================================================================

echo "[$(date '+%H:%M:%S')] Resetting IDPS environment..."

# 1. Flush iptables INPUT chain
echo "  → Flushing iptables INPUT chain..."
sudo iptables -F INPUT 2>/dev/null
sudo iptables -A INPUT -j ACCEPT 2>/dev/null
echo "    iptables flushed: $(sudo iptables -L INPUT -n | wc -l) rules remaining"

# 2. Clear blacklist
BLACKLIST_PATHS=(
    "/app/configs/blacklist.json"
    "/home/dmtien/IDPS/configs/blacklist.json"
)
for path in "${BLACKLIST_PATHS[@]}"; do
    if [ -f "$path" ] || [ -d "$(dirname "$path")" ]; then
        echo '{"description":"IP Blacklist - Reset for testing","ips":[]}' | sudo tee "$path" > /dev/null 2>/dev/null
        echo "    Blacklist cleared: $path"
    fi
done

# 3. Không restart container (giữ NFStream chạy liên tục)
echo "  → Containers giữ nguyên (không restart)"

# 4. Optional: Clear Suricata fast.log (giữ eve.json cho correlation)
# sudo truncate -s 0 /var/log/suricata/fast.log 2>/dev/null

echo "[$(date '+%H:%M:%S')] Reset hoàn tất."
echo "  iptables: ACCEPT all"
echo "  blacklist: empty"
echo "  containers: running"
