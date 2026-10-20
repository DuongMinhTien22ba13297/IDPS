#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PROJECT_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)

cd "$PROJECT_DIR/docker"
MONITOR_ONLY_MODE=false \
SURICATA_ONLY_MODE=false \
TEST_RUN_ID=production \
docker compose up -d --force-recreate autodefense

docker inspect autodefense --format '{{range .Config.Env}}{{println .}}{{end}}' \
    | grep -E '^(MONITOR_ONLY_MODE|SURICATA_ONLY_MODE|TEST_RUN_ID)='
