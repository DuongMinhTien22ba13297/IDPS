#!/bin/bash

# Scenario 06: Evasion Techniques
# Mục tiêu  : Chứng minh ML vượt trội so với pure signature IDS (Suricata)
#              bằng cách sử dụng kỹ thuật né tránh IDS truyền thống.
# Công cụ   : nmap (bắt buộc)
# Techniques: Fragmentation → Decoy → Ultra-Slow → Timing Randomization


TARGET="${1:-172.16.1.2}"
LOG_DIR="${2:-/tmp/idps_test_logs}"
SCENARIO_NAME="06_evasion"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

mkdir -p "$LOG_DIR"
LOGFILE="$LOG_DIR/${SCENARIO_NAME}.log"

log() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOGFILE"
}

# Kiểm tra nmap
if ! command -v nmap &>/dev/null; then
    log "ERROR: nmap không tìm thấy."
    exit 1
fi


log "SCENARIO 06: Evasion Techniques → $TARGET"
log "Mục đích: Chứng minh ML bắt được attack dù Suricata bỏ sót"


# Technique 1: Packet Fragmentation
# Suricata DPI cần reassemble packets → fragment nhỏ có thể bypass
# ML vẫn bắt vì NFStream reassemble ở flow level

log "TECHNIQUE 1: Packet Fragmentation"
log "Suricata: MISS (fragments quá nhỏ, DPI không reassemble kịp)"
log "ML: CATCH (NFStream tổng hợp flow, IAT/SYN Flag Count bất thường)"


log "[1.1] 8-byte MTU fragments"
nmap -f --mtu 8 -sS -p 22,80,443,3000,3001 "$TARGET" \
    -oN "$LOG_DIR/${SCENARIO_NAME}_frag8.txt" 2>&1 | tail -5 | tee -a "$LOGFILE"

bash "$SCRIPT_DIR/unblock_and_reset.sh"


log "[1.2] 16-byte fragments (double fragmentation)"
nmap -f -f -sS -p 1-100 "$TARGET" \
    -oN "$LOG_DIR/${SCENARIO_NAME}_frag16.txt" 2>&1 | tail -5 | tee -a "$LOGFILE"

bash "$SCRIPT_DIR/unblock_and_reset.sh"


log "[1.3] Custom MTU 24 bytes"
nmap --mtu 24 -sS -p 22,80,443 "$TARGET" \
    -oN "$LOG_DIR/${SCENARIO_NAME}_mtu24.txt" 2>&1 | tail -5 | tee -a "$LOGFILE"

bash "$SCRIPT_DIR/unblock_and_reset.sh"

# Technique 2: Decoy Scan
# Thêm source IP giả → khó biết IP thật nào đang scan
# ML vẫn bắt vì SYN packets từ IP thật vẫn tạo flow

log "TECHNIQUE 2: Decoy Scan (IP giả lẫn IP thật)"
log "Suricata: CONFUSED (nhiều source IP, threshold tính riêng mỗi IP)"
log "ML: CATCH (flow từ IP thật vẫn có pattern scan rõ ràng)"


log "[2.1] 10 random decoy IPs"
nmap -D RND:10 -sS -p 1-100 "$TARGET" \
    -oN "$LOG_DIR/${SCENARIO_NAME}_decoy_random.txt" 2>&1 | tail -5 | tee -a "$LOGFILE"

bash "$SCRIPT_DIR/unblock_and_reset.sh"


log "[2.2] Decoy với IP cụ thể + ME (IP thật)"
nmap -D 10.0.0.1,10.0.0.2,10.0.0.3,10.0.0.4,10.0.0.5,ME -sS -p 22,80,443 "$TARGET" \
    -oN "$LOG_DIR/${SCENARIO_NAME}_decoy_specific.txt" 2>&1 | tail -5 | tee -a "$LOGFILE"

bash "$SCRIPT_DIR/unblock_and_reset.sh"

# Technique 3: Ultra-Slow Scan
# T0 (Paranoid) = ~5 phút/port → dưới mọi IDS threshold
# ML bắt khi NFStream flush flow sau idle_timeout (10s)

log "TECHNIQUE 3: Ultra-Slow Scan (T0 Paranoid)"
log "Suricata: MISS (0 alerts, quá chậm để trigger threshold)"
log "ML: CATCH (sau NFStream idle_timeout, flow stats vẫn bất thường)"


log "[3.1] T0 scan (3 ports only — quá chậm nên giới hạn)"
log "      → Mỗi port mất ~5 phút, chỉ scan 3 ports cho demo"
timeout 120 nmap -sS -T0 -p 22,80,443 "$TARGET" \
    -oN "$LOG_DIR/${SCENARIO_NAME}_t0.txt" 2>&1 | tail -5 | tee -a "$LOGFILE"

bash "$SCRIPT_DIR/unblock_and_reset.sh"


log "[3.2] T1 scan với delay 2 giây (nhanh hơn T0, vẫn chậm)"
nmap -sS -T1 --scan-delay 2000ms --max-retries 1 -p 1-30 "$TARGET" \
    -oN "$LOG_DIR/${SCENARIO_NAME}_t1_delay.txt" 2>&1 | tail -5 | tee -a "$LOGFILE"

bash "$SCRIPT_DIR/unblock_and_reset.sh"

# Technique 4: Timing Randomization
# Random delay giữa các probe → phá vỡ IAT pattern cố định
# ML vẫn bắt qua IAT Std cao (variance lớn = scan behavior)

log "TECHNIQUE 4: Timing Randomization"
log "Suricata: MISS (delay ngẫu nhiên, không đạt threshold)"
log "ML: CATCH (IAT Std rất cao do random delays, Packet Length Std thấp)"


log "[4.1] Random delay 500-5000ms"
nmap -sS --scan-delay 500ms --max-scan-delay 5000ms \
    --max-retries 0 -p 1-50 "$TARGET" \
    -oN "$LOG_DIR/${SCENARIO_NAME}_random_delay.txt" 2>&1 | tail -5 | tee -a "$LOGFILE"

bash "$SCRIPT_DIR/unblock_and_reset.sh"


log "[4.2] Xen kẽ: scan 5 ports → nghỉ 10s → scan tiếp"
for batch in 1 2 3 4; do
    start_port=$(( (batch - 1) * 5 + 1 ))
    end_port=$(( batch * 5 ))
    log "      Batch $batch: ports $start_port-$end_port"
    nmap -sS -T3 -p "$start_port-$end_port" "$TARGET" -oN /dev/null 2>&1 | tail -2 | tee -a "$LOGFILE"
    bash "$SCRIPT_DIR/unblock_and_reset.sh"
done



log "SCENARIO 06 HOÀN TẤT"

log "KẾT QUẢ KỲ VỌNG:"
log "  Suricata-only: 0-1 alerts (hầu hết kỹ thuật né được)"
log "  Full System (ML): 4/4 techniques phát hiện thành công"

