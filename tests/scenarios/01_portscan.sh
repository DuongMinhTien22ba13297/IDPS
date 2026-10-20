#!/bin/bash

# Scenario 01: PortScan Multi-Phase
# Mục tiêu  : Test khả năng phát hiện port scan ở nhiều mức độ khác nhau.
# Công cụ   : nmap (bắt buộc)
# Phases    : Stealth (T1/NULL) → Aggressive (T4) → Service Enumeration (NSE)


TARGET="${1:-172.16.1.2}"
LOG_DIR="${2:-/tmp/idps_test_logs}"
SCENARIO_NAME="01_portscan"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

mkdir -p "$LOG_DIR"
LOGFILE="$LOG_DIR/${SCENARIO_NAME}.log"

log() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOGFILE"
}

#Kiểm tra nmap
if ! command -v nmap &>/dev/null; then
    log "ERROR: nmap không tìm thấy. Bỏ qua scenario này."
    exit 1
fi


log "SCENARIO 01: PortScan Multi-Phase → $TARGET"


#PHASE 1: Stealthy Reconnaissance
# Mục đích: Tạo traffic scan chậm mà Suricata có thể bỏ sót,
# nhưng ML nhận ra qua IAT Std, SYN Flag Count bất thường.

log "PHASE 1: Stealthy Reconnaissance (Suricata có thể miss)"

log "[1.1] TCP SYN Scan cực chậm (T1, delay 500ms)"
log "      → Suricata threshold khó trigger vì quá ít packets/s"
nmap -sS -T1 --scan-delay 500ms -p 22,80,443,3000,3001,8080 "$TARGET" \
    -oN "$LOG_DIR/${SCENARIO_NAME}_phase1_syn_slow.txt" 2>&1 | tail -5 | tee -a "$LOGFILE"

bash "$SCRIPT_DIR/unblock_and_reset.sh"


log "[1.2] TCP NULL Scan (không gửi SYN flag → bypass SYN-based rules)"
log "      → Suricata rule 'flags:S' sẽ không match"
nmap -sN -T2 -p 1-100 "$TARGET" \
    -oN "$LOG_DIR/${SCENARIO_NAME}_phase1_null.txt" 2>&1 | tail -5 | tee -a "$LOGFILE"

bash "$SCRIPT_DIR/unblock_and_reset.sh"


log "[1.3] FIN Scan (chỉ gửi FIN flag)"
log "      → Kỹ thuật evasion cổ điển, ML nhận qua FIN Flag Count bất thường"
nmap -sF -T2 -p 1-50 "$TARGET" \
    -oN "$LOG_DIR/${SCENARIO_NAME}_phase1_fin.txt" 2>&1 | tail -5 | tee -a "$LOGFILE"

bash "$SCRIPT_DIR/unblock_and_reset.sh"

#PHASE 2: Aggressive Discovery
# Mục đích: Scan nhanh, tạo nhiều SYN packets → trigger cả Suricata lẫn ML

log "PHASE 2: Aggressive Discovery (Suricata + ML đều bắt)"

log "[2.1] Full TCP SYN Scan + OS Detection + Service Version"
log "      → Rất nhiều packets, Flow Packets/s cao → ML classify PortScan"
nmap -sS -sV -O -A -T4 -p 1-1000 "$TARGET" \
    -oN "$LOG_DIR/${SCENARIO_NAME}_phase2_aggressive.txt" 2>&1 | tail -10 | tee -a "$LOGFILE"

bash "$SCRIPT_DIR/unblock_and_reset.sh"


log "[2.2] UDP Scan (top 50 ports, protocol khác)"
log "      → Chứng minh ML phát hiện scan bất kể protocol"
nmap -sU -T4 --top-ports 50 "$TARGET" \
    -oN "$LOG_DIR/${SCENARIO_NAME}_phase2_udp.txt" 2>&1 | tail -5 | tee -a "$LOGFILE"

bash "$SCRIPT_DIR/unblock_and_reset.sh"

#PHASE 3: Service Enumeration
# Mục đích: Dò sâu vào dịch vụ → nhiều connection attempts tới ít port

log "PHASE 3: Service Enumeration (Deep Fingerprinting)"

log "[3.1] NSE Scripts: default + banner + http-title"
log "      → Nhiều request HTTP/SSH → ML thấy pattern enumeration"
nmap -sV --version-intensity 9 \
     --script=default,banner,http-title,ssh-hostkey \
     -p 22,80,443,3000,3001 "$TARGET" \
    -oN "$LOG_DIR/${SCENARIO_NAME}_phase3_nse.txt" 2>&1 | tail -10 | tee -a "$LOGFILE"

bash "$SCRIPT_DIR/unblock_and_reset.sh"


log "[3.2] Vuln scan (tìm CVE)"
log "      → Rất nhiều probes → Port_Conn_Rate cao"
nmap --script=vuln -p 22,80,443 "$TARGET" \
    -oN "$LOG_DIR/${SCENARIO_NAME}_phase3_vuln.txt" 2>&1 | tail -10 | tee -a "$LOGFILE"



log "SCENARIO 01 HOÀN TẤT"
log "Logs: $LOG_DIR/${SCENARIO_NAME}_*.txt"

