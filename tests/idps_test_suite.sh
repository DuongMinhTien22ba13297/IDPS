#!/bin/bash
# =============================================================================
# IDPS Test Suite — Master Script
# Mục tiêu  : Chạy tuần tự 6 kịch bản tấn công, reset môi trường giữa mỗi kịch bản,
#              và ghi marker timestamps để collect_metrics.py parse log sau.
# Chạy trên : Máy Kali Linux (172.16.1.10)
# Target    : IDPS Server (172.16.1.2)
# Ngày tạo  : 2026-06-06
#
# CÁCH DÙNG:
#   chmod +x idps_test_suite.sh scenarios/*.sh
#   sudo ./idps_test_suite.sh [--skip-reset] [--scenario N] [--fast]
#
# TÙY CHỌN:
#   --skip-reset   : Không reset môi trường giữa các kịch bản
#   --scenario N   : Chỉ chạy kịch bản N (1-6)
#   --fast         : Giảm thời gian chờ (cho test nhanh)
#   --install-deps : Cài đặt các tool thiếu trước khi chạy
# =============================================================================

set -e

# ── Cấu hình ──
TARGET="172.16.1.2"
SERVER_USER="dmtien"
SSH_TARGET=""  # Sẽ được cấu hình qua tham số hoặc tự động dò tìm
LOG_DIR="/tmp/idps_test_logs"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCENARIOS_DIR="$SCRIPT_DIR/scenarios"
TIMESTAMP_FILE="$LOG_DIR/test_timestamps.json"

# Tự động tìm SSH private key của user gốc gọi sudo để SSH sang Server
SSH_KEY_OPT=""
if [ -n "$SUDO_USER" ]; then
    SUDO_USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    if [ -f "$SUDO_USER_HOME/.ssh/id_ed25519" ]; then
        SSH_KEY_OPT="-i $SUDO_USER_HOME/.ssh/id_ed25519"
    elif [ -f "$SUDO_USER_HOME/.ssh/id_rsa" ]; then
        SSH_KEY_OPT="-i $SUDO_USER_HOME/.ssh/id_rsa"
    fi
fi

# ── Parse arguments ──
SKIP_RESET=false
SINGLE_SCENARIO=0
FAST_MODE=false
INSTALL_DEPS=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-reset)   SKIP_RESET=true; shift ;;
        --scenario)     SINGLE_SCENARIO="$2"; shift 2 ;;
        --fast)         FAST_MODE=true; shift ;;
        --install-deps) INSTALL_DEPS=true; shift ;;
        --ssh-target)   SSH_TARGET="$2"; shift 2 ;;
        *)              echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Thiết lập mặc định cho SSH_TARGET nếu không truyền
# Tự động ping thử IP quản trị 192.168.226.151, nếu thông thì chọn làm SSH target, ngược lại fallback về TARGET
if [ -z "$SSH_TARGET" ]; then
    DEFAULT_ADMIN_IP="192.168.226.151"
    if ping -c 1 -W 1 "$DEFAULT_ADMIN_IP" &>/dev/null; then
        SSH_TARGET="$DEFAULT_ADMIN_IP"
    else
        SSH_TARGET="$TARGET"
    fi
fi

# ── Thời gian chờ giữa kịch bản ──
if $FAST_MODE; then
    WAIT_BETWEEN=15      # 15s cho fast mode
    WAIT_AFTER_RESET=10  # 10s sau reset
else
    WAIT_BETWEEN=30      # 30s cho normal mode
    WAIT_AFTER_RESET=20  # 20s sau reset
fi

# ── Logging ──
mkdir -p "$LOG_DIR"
MASTER_LOG="$LOG_DIR/master.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$MASTER_LOG"
}

log_marker() {
    # Ghi marker JSON cho collect_metrics.py
    local scenario_name="$1"
    local phase="$2"  # "start" hoặc "end"
    local ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo "{\"scenario\": \"$scenario_name\", \"phase\": \"$phase\", \"timestamp\": \"$ts\"}" >> "$TIMESTAMP_FILE"
}

cleanup_attack_processes() {
    log "Dọn dẹp triệt để các tiến trình tấn công mồ côi trên Kali..."
    # Không dùng -f cho binary để tránh pkill tự sát
    sudo pkill -9 "^nmap$" 2>/dev/null || true
    sudo pkill -9 "^hping3$" 2>/dev/null || true
    sudo pkill -9 "^hydra$" 2>/dev/null || true
    sudo pkill -9 "^medusa$" 2>/dev/null || true
    sudo pkill -9 "^ncrack$" 2>/dev/null || true
    sudo pkill -9 "^slowhttptest$" 2>/dev/null || true
    # Dùng ngoặc vuông để tránh pkill -f tự khớp chính mình
    sudo pkill -9 -f "[s]lowloris_fallback" 2>/dev/null || true
    sudo pkill -9 -f "[s]yn_flood_fallback" 2>/dev/null || true
    sudo pkill -9 -f "[b]otnet_sim" 2>/dev/null || true
}

# Đăng ký trap dọn dẹp khi script bị dừng đột ngột (Ctrl+C, EXIT, TERM)
trap cleanup_attack_processes EXIT INT TERM

# ── Banner ──
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           IDPS ROBUST TEST SUITE v1.0                      ║"
echo "║           Target: $TARGET                            ║"
echo "║           Date: $(date '+%Y-%m-%d %H:%M:%S')                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

log "================================================================"
log "IDPS TEST SUITE STARTED"
log "Target: $TARGET"
log "Fast mode: $FAST_MODE"
log "Skip reset: $SKIP_RESET"
log "Single scenario: $SINGLE_SCENARIO"
log "================================================================"

# ── Pre-flight: Kiểm tra tools ──
echo ""
echo "┌─ PRE-FLIGHT CHECK ─────────────────────────────────────────┐"
TOOLS_STATUS=()
check_tool() {
    local tool="$1"
    local required="$2"
    if command -v "$tool" &>/dev/null; then
        echo "│  ✅ $tool"
        TOOLS_STATUS+=("$tool:OK")
    else
        if [ "$required" = "required" ]; then
            echo "│  ❌ $tool (BẮT BUỘC)"
        else
            echo "│  ⚠️  $tool (tùy chọn, có fallback)"
        fi
        TOOLS_STATUS+=("$tool:MISSING")
    fi
}

check_tool "nmap"          "required"
check_tool "hydra"         "required"
check_tool "curl"          "required"
check_tool "python3"       "required"
check_tool "hping3"        "optional"
check_tool "medusa"        "optional"
check_tool "ncrack"        "optional"
check_tool "sqlmap"        "optional"
check_tool "nikto"         "optional"
check_tool "gobuster"      "optional"
check_tool "slowhttptest"  "optional"
check_tool "wfuzz"         "optional"
echo "└───────────────────────────────────────────────────────────┘"
echo ""

# Cài đặt tools thiếu nếu được yêu cầu
if $INSTALL_DEPS; then
    echo "Đang cài đặt tools thiếu..."
    for entry in "${TOOLS_STATUS[@]}"; do
        tool="${entry%%:*}"
        status="${entry##*:}"
        if [ "$status" = "MISSING" ]; then
            log "Installing $tool..."
            sudo apt install -y "$tool" 2>/dev/null || log "WARN: Không thể cài $tool"
        fi
    done
    echo ""
fi

# Kiểm tra tools bắt buộc
for tool in nmap hydra curl python3; do
    if ! command -v "$tool" &>/dev/null; then
        log "FATAL: $tool không tìm thấy. Chạy lại với --install-deps"
        exit 1
    fi
done

# ── Pre-flight: Kiểm tra kết nối tới target ──
echo "┌─ CONNECTIVITY CHECK ───────────────────────────────────────┐"
if ping -c 1 -W 2 "$TARGET" &>/dev/null; then
    echo "│  ✅ Ping $TARGET: OK"
else
    echo "│  ⚠️  Ping $TARGET: FAILED (có thể bị block ICMP)"
fi

if curl -sk --connect-timeout 5 "https://$TARGET" &>/dev/null; then
    echo "│  ✅ HTTPS $TARGET: OK (Juice Shop reachable)"
else
    echo "│  ⚠️  HTTPS $TARGET: FAILED (Juice Shop có thể chưa chạy)"
fi

if ssh -o ConnectTimeout=3 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $SSH_KEY_OPT "$SERVER_USER@$SSH_TARGET" "echo OK" 2>/dev/null; then
    echo "│  ✅ SSH $SSH_TARGET: OK (có thể reset từ xa)"
    SSH_AVAILABLE=true
else
    echo "│  ⚠️  SSH $SSH_TARGET: FAILED (sẽ không reset tự động)"
    SSH_AVAILABLE=false
fi
echo "└───────────────────────────────────────────────────────────┘"
echo ""

# Đọc ban_duration_seconds từ server nếu SSH khả dụng
BAN_DURATION=60
if [ "$SSH_AVAILABLE" = "true" ]; then
    log "Đọc cấu hình ban_duration_seconds từ IDPS Server..."
    SERVER_BAN_DURATION=$(ssh -o ConnectTimeout=3 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $SSH_KEY_OPT "$SERVER_USER@$SSH_TARGET" "docker exec autodefense python3 -c \"import json; print(json.load(open('/app/configs/thresholds.json')).get('ban_duration_seconds', 60))\"" 2>/dev/null || echo "")
    if [ -n "$SERVER_BAN_DURATION" ] && [[ "$SERVER_BAN_DURATION" =~ ^[0-9]+$ ]]; then
        BAN_DURATION=$SERVER_BAN_DURATION
        log "Lấy ban_duration_seconds từ Server thành công: ${BAN_DURATION}s"
    else
        log "Không đọc được ban_duration_seconds từ Server, sử dụng mặc định: ${BAN_DURATION}s"
    fi
fi

# Xuất các biến môi trường để các scenario con thừa hưởng
export TARGET
export SERVER_USER
export SSH_TARGET
export SSH_KEY_OPT
export WAIT_BETWEEN
export WAIT_AFTER_RESET
export BAN_DURATION
export SKIP_RESET
export SSH_AVAILABLE

# ── Khởi tạo timestamp file ──
echo "[]" > "$TIMESTAMP_FILE"

# ── Hàm reset môi trường ──
reset_environment() {
    # Dọn dẹp tiến trình tấn công mồ côi trước khi unblock
    cleanup_attack_processes

    # Chạy script unblock và reset môi trường chung
    bash "$SCRIPT_DIR/unblock_and_reset.sh"
}

# ── Hàm chạy scenario ──
run_scenario() {
    local num="$1"
    local name="$2"
    local script="$SCENARIOS_DIR/${num}_${name}.sh"

    if [ ! -f "$script" ]; then
        log "WARN: Script $script không tồn tại. Bỏ qua."
        return
    fi

    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  SCENARIO $num: $(echo "$name" | tr '[:lower:]' '[:upper:]')"
    echo "║  Script: $script"
    echo "║  Started: $(date '+%H:%M:%S')"
    echo "╚══════════════════════════════════════════════════════════════╝"

    log_marker "$name" "start"
    log "SCENARIO $num ($name) — STARTED"

    # Chạy scenario script
    chmod +x "$script"
    bash "$script" "$TARGET" "$LOG_DIR" 2>&1

    log_marker "$name" "end"
    log "SCENARIO $num ($name) — COMPLETED"

    # Đợi giữa kịch bản (cho NFStream flush)
    log "Đợi ${WAIT_BETWEEN}s trước kịch bản tiếp theo..."
    sleep "$WAIT_BETWEEN"

    # Reset môi trường
    reset_environment
}

# ── Inject benign traffic (đo False Positive) ──
inject_benign() {
    log "Injecting benign traffic (đo False Positive Rate)..."
    log_marker "benign_baseline" "start"

    # 20 request HTTP bình thường
    for i in $(seq 1 20); do
        curl -sk -o /dev/null "https://$TARGET/" &
        curl -sk -o /dev/null "https://$TARGET/rest/products/search?q=apple" &
    done
    wait

    # Ping bình thường
    ping -c 10 -i 0.5 "$TARGET" > /dev/null 2>&1 || true

    log_marker "benign_baseline" "end"
    log "Benign traffic injection hoàn tất (20 HTTP + 10 ping)"
}

# ── MAIN EXECUTION ──

# Bước 0: Inject benign baseline
inject_benign

# Bước 1: Reset ban đầu
reset_environment

# Bước 2: Chạy scenarios
if [ "$SINGLE_SCENARIO" -gt 0 ]; then
    # Chạy 1 scenario cụ thể
    case "$SINGLE_SCENARIO" in
        1) run_scenario "01" "portscan" ;;
        2) run_scenario "02" "bruteforce" ;;
        3) run_scenario "03" "dos" ;;
        4) run_scenario "04" "web_attack" ;;
        5) run_scenario "05" "botnet" ;;
        6) run_scenario "06" "evasion" ;;
        *) log "ERROR: Scenario $SINGLE_SCENARIO không tồn tại (1-6)"; exit 1 ;;
    esac
else
    # Chạy tất cả scenarios tuần tự
    run_scenario "01" "portscan"
    run_scenario "02" "bruteforce"
    run_scenario "03" "dos"
    run_scenario "04" "web_attack"
    run_scenario "05" "botnet"
    run_scenario "06" "evasion"
fi

# Bước 3: Inject benign cuối (đo FP sau khi hệ thống đã "nóng")
inject_benign

# ── Summary ──
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           TEST SUITE COMPLETED                              ║"
echo "║           $(date '+%Y-%m-%d %H:%M:%S')                          ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Logs directory: $LOG_DIR"
echo "Timestamps: $TIMESTAMP_FILE"
echo ""
echo "Bước tiếp theo:"
echo "  1. SSH vào server: ssh $SERVER_USER@$TARGET"
echo "  2. Chạy collect_metrics.py để lấy số liệu:"
echo "     python3 tests/collect_metrics.py --log /app/logs/action_audit.log"
echo ""

log "================================================================"
log "TEST SUITE COMPLETED"
log "================================================================"
