#!/bin/bash
# =============================================================================
# IDPS Test Suite — Unblock & Reset Helper
# Mục tiêu  : Kiểm tra trạng thái chặn của IP Kali, unblock nếu bị chặn,
#              reset iptables/blacklist trên server, và chờ NFStream flush flows.
# Chạy trên : Máy Kali Linux (172.16.1.10)
# Target    : IDPS Server (172.16.1.2)
# =============================================================================

# Thiết lập mặc định nếu không thừa hưởng biến môi trường
TARGET="${TARGET:-172.16.1.2}"
SERVER_USER="${SERVER_USER:-dmtien}"
SSH_TARGET="${SSH_TARGET:-}"
SSH_KEY_OPT="${SSH_KEY_OPT:-}"
WAIT_AFTER_RESET="${WAIT_AFTER_RESET:-20}"
BAN_DURATION="${BAN_DURATION:-60}"
SKIP_RESET="${SKIP_RESET:-false}"
SSH_AVAILABLE="${SSH_AVAILABLE:-true}"

# Tự động tìm SSH private key nếu chạy bằng sudo và chưa có SSH_KEY_OPT
if [ -z "$SSH_KEY_OPT" ] && [ -n "$SUDO_USER" ]; then
    SUDO_USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    if [ -f "$SUDO_USER_HOME/.ssh/id_ed25519" ]; then
        SSH_KEY_OPT="-i $SUDO_USER_HOME/.ssh/id_ed25519"
    elif [ -f "$SUDO_USER_HOME/.ssh/id_rsa" ]; then
        SSH_KEY_OPT="-i $SUDO_USER_HOME/.ssh/id_rsa"
    fi
fi

# Tự động dò tìm SSH_TARGET nếu trống
if [ -z "$SSH_TARGET" ]; then
    DEFAULT_ADMIN_IP="192.168.226.151"
    if ping -c 1 -W 1 "$DEFAULT_ADMIN_IP" &>/dev/null; then
        SSH_TARGET="$DEFAULT_ADMIN_IP"
    else
        SSH_TARGET="$TARGET"
    fi
fi

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [UNBLOCK-RESET] $1"
}

if $SKIP_RESET; then
    log "Bỏ qua reset môi trường theo cấu hình --skip-reset."
    exit 0
fi

# Lấy IP test của Kali
kali_test_ip=$(ip route get "$TARGET" 2>/dev/null | grep -oP 'src \K\S+' || echo "172.16.1.10")

log "Kiểm tra trạng thái chặn của IP Kali ($kali_test_ip) trên Server..."
is_blocked=false

# 1. Kiểm tra rule block trong iptables thông qua SSH
if ssh -o ConnectTimeout=3 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $SSH_KEY_OPT "$SERVER_USER@$SSH_TARGET" "docker exec autodefense iptables -C INPUT -s $kali_test_ip -j DROP" &>/dev/null; then
    is_blocked=true
else
    # 2. Nếu không SSH được (có thể do đường truyền chính bị block), thử check xem ping có thông hoặc SSH có timeout không
    if ! ssh -o ConnectTimeout=3 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $SSH_KEY_OPT "$SERVER_USER@$SSH_TARGET" "echo OK" &>/dev/null; then
        is_blocked=true
    fi
fi

if [ "$is_blocked" = "true" ]; then
    log "⚠️  IP test của Kali ($kali_test_ip) đang bị block trên Server."
    if [ "$SSH_AVAILABLE" = "true" ]; then
        log "⚡ Gửi lệnh unblock cưỡng bức qua SSH quản trị ($SSH_TARGET)..."
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $SSH_KEY_OPT "$SERVER_USER@$SSH_TARGET" 'bash -s' << 'RESET_EOF'
            docker exec autodefense iptables -F INPUT 2>/dev/null
            docker exec autodefense iptables -A INPUT -j ACCEPT 2>/dev/null
            docker exec autodefense sh -c "echo '{\"description\":\"IP Blacklist\",\"ips\":[]}' > /app/configs/blacklist.json" 2>/dev/null
            echo "Reset OK"
RESET_EOF
        # Kiểm tra lại xem đã unblock thành công chưa
        if ! ssh -o ConnectTimeout=3 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $SSH_KEY_OPT "$SERVER_USER@$SSH_TARGET" "docker exec autodefense iptables -C INPUT -s $kali_test_ip -j DROP" &>/dev/null; then
            log "✅ Đã unblock IP Kali ($kali_test_ip) thành công!"
            is_blocked=false
        fi
    fi
fi

if [ "$is_blocked" = "true" ]; then
    # Fallback nếu unblock qua SSH thất bại (ví dụ dùng chung đường truyền và bị block): Đợi unblock tự động
    if [ "$SSH_TARGET" != "$TARGET" ]; then
        log "⏱️  Đang đợi IDPS Server tự động unblock (Kiểm tra qua SSH quản trị $SSH_TARGET)..."
        elapsed=0
        timeout=180
        while [ $elapsed -lt $timeout ]; do
            if ! ssh -o ConnectTimeout=3 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $SSH_KEY_OPT "$SERVER_USER@$SSH_TARGET" "docker exec autodefense iptables -C INPUT -s $kali_test_ip -j DROP" &>/dev/null; then
                log "✅ Xác nhận: IDPS Server đã tự động unblock IP Kali ($kali_test_ip) sau ${elapsed}s!"
                is_blocked=false
                break
            fi
            sleep 5
            elapsed=$((elapsed + 5))
        done
        if [ "$is_blocked" = "true" ]; then
            log "❌ Quá thời gian chờ unblock tự động ($timeout giây)."
        fi
    else
        # Dùng chung đường truyền: im lặng tuyệt đối
        silence_sleep=$((BAN_DURATION + 30))
        log "⏱️  Đang đợi IDPS Server tự động unblock..."
        log "👉 Do dùng chung đường kết nối, Kali sẽ IM LẶNG HOÀN TOÀN trong ${silence_sleep} giây để tránh slide TTL..."
        remaining=$silence_sleep
        while [ $remaining -gt 0 ]; do
            echo -ne "⏱️  Còn lại ${remaining}s...\r"
            sleep 1
            remaining=$((remaining - 1))
        done
        echo ""
        
        log "Kiểm tra lại kết nối SSH sau thời gian im lặng..."
        if ssh -o ConnectTimeout=5 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $SSH_KEY_OPT "$SERVER_USER@$SSH_TARGET" "echo OK" &>/dev/null; then
            log "✅ Kết nối SSH tới $SSH_TARGET đã được khôi phục!"
            is_blocked=false
        fi
    fi
fi

log "Resetting environment trên $SSH_TARGET (iptables + blacklist)..."
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $SSH_KEY_OPT "$SERVER_USER@$SSH_TARGET" 'bash -s' << 'RESET_EOF'
    # Flush iptables INPUT chain (xóa hết DROP rules)
    docker exec autodefense iptables -F INPUT 2>/dev/null
    docker exec autodefense iptables -A INPUT -j ACCEPT 2>/dev/null
    # Clear blacklist
    docker exec autodefense sh -c "echo '{\"description\":\"IP Blacklist\",\"ips\":[]}' > /app/configs/blacklist.json" 2>/dev/null
    echo "Reset OK: iptables flushed + blacklist cleared"
RESET_EOF

log "Đợi ${WAIT_AFTER_RESET}s cho NFStream flush các flows cũ..."
sleep "$WAIT_AFTER_RESET"
log "Reset môi trường hoàn tất."
