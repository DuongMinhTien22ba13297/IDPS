#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ! "$1" =~ ^[A-Za-z0-9_.-]{1,64}$ ]]; then
    echo "Usage: $0 RUN_ID (letters, digits, dot, underscore or dash; max 64)" >&2
    exit 2
fi

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PROJECT_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)
RUN_ID=$1

cd "$PROJECT_DIR/docker"
MONITOR_ONLY_MODE=true \
SURICATA_ONLY_MODE=false \
TEST_RUN_ID="$RUN_ID" \
docker compose up -d --force-recreate autodefense

docker inspect autodefense --format '{{range .Config.Env}}{{println .}}{{end}}' \
    | grep -E '^(MONITOR_ONLY_MODE|SURICATA_ONLY_MODE|TEST_RUN_ID|SURICATA_RELATED_PORTS)='
docker logs --tail 30 autodefense 2>&1 \
    | grep -E 'Run ID:|MONITOR_ONLY_MODE|Pipeline:|ERROR|Traceback' || true
