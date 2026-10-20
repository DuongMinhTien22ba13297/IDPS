#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${1:-/home/dmtien/IDPS}"
INTERFACE="idps-smoke0"
PEER_INTERFACE="idps-smoke1"
SOURCE_IP="198.18.0.10"
DESTINATION_IP="198.18.0.20"
OUTPUT_FILE="${REPO_DIR}/logs/runtime21_staging/e2e_daemon_smoke_final.log"
INJECTOR="${REPO_DIR}/logs/runtime21_staging/live_packet_injector.py"
DESTINATION_MAC="$(cat "/sys/class/net/${INTERFACE}/address")"

send_test_flows() {
    sleep 10
    python3 "${INJECTOR}" \
        --interface "${PEER_INTERFACE}" \
        --source-ip "${SOURCE_IP}" \
        --destination-ip "${DESTINATION_IP}" \
        --destination-mac "${DESTINATION_MAC}" \
        --count 1 --start-port 22400 --close-with-rst
    sleep 12
    python3 "${INJECTOR}" \
        --interface "${PEER_INTERFACE}" \
        --source-ip "${SOURCE_IP}" \
        --destination-ip "${DESTINATION_IP}" \
        --destination-mac "${DESTINATION_MAC}" \
        --count 1 --start-port 22401 --close-with-rst
}

send_test_flows &
SENDER_PID=$!

set +e
docker exec autodefense sh -c \
    "IFACE=${INTERFACE} timeout -s INT 40 python3 /app/src/autodefense_daemon.py > /app/logs/runtime21_staging/e2e_daemon_smoke_final.log 2>&1"
DAEMON_STATUS=$?
set -e
wait "${SENDER_PID}"

if [[ "${DAEMON_STATUS}" -ne 0 && "${DAEMON_STATUS}" -ne 124 ]]; then
    echo "daemon smoke process failed with status ${DAEMON_STATUS}" >&2
    exit "${DAEMON_STATUS}"
fi

grep -F "Model experiment: 20260908_botnet_excluded_v1 | Features: 21" "${OUTPUT_FILE}"
grep -F "Flow " "${OUTPUT_FILE}" | grep -F "from ${SOURCE_IP}: BENIGN" | grep -F "Port: 22400"
grep -F '"event_type": "ml_probs"' "${OUTPUT_FILE}" | grep -F "${SOURCE_IP}" | grep -F '"dst_port": 22400'

echo "E2E_LIVE_DAEMON_SMOKE_PASS"
