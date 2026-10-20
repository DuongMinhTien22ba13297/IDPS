#!/bin/bash

# Scenario 05: Botnet C&C Simulation
# Mục tiêu  : Test phát hiện traffic pattern bất thường kiểu Botnet
# Công cụ   : python3 (bắt buộc - có sẵn trên Kali)
# Phases    : C&C Beacon → Data Exfiltration → Internal Recon


TARGET="${1:-172.16.1.2}"
LOG_DIR="${2:-/tmp/idps_test_logs}"
SCENARIO_NAME="05_botnet"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS_DIR="$SCRIPT_DIR/tools"

mkdir -p "$LOG_DIR"
LOGFILE="$LOG_DIR/${SCENARIO_NAME}.log"

log() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOGFILE"
}

# Kiểm tra python3
if ! command -v python3 &>/dev/null; then
    log "ERROR: python3 không tìm thấy."
    exit 1
fi


log "SCENARIO 05: Botnet C&C Simulation → $TARGET"


# Chạy botnet simulation (fast mode cho test)

log "Khởi chạy botnet_sim.py (fast mode)..."
log "  → Phase 1: C&C Beacon (15 cycles, 3-8s interval)"
log "  → Phase 2: Data Exfiltration (8 cycles)"
log "  → Phase 3: Internal Port Probe (30 ports)"

log "  ML sẽ nhận diện qua:"
log "    - IAT pattern periodic (C&C beacon)"
log "    - Forward bytes >> Backward bytes (data exfil)"
log "    - Multi-port probing từ cùng src_ip"

python3 "$TOOLS_DIR/botnet_sim.py" \
    --target "$TARGET" \
    --beacon-cycles 15 \
    --exfil-cycles 8 \
    --fast \
    2>&1 | tee "$LOG_DIR/${SCENARIO_NAME}_botnet.txt" | tee -a "$LOGFILE"



log "SCENARIO 05 HOÀN TẤT"
log "Logs: $LOG_DIR/${SCENARIO_NAME}_*.txt"

