#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.env"

if [[ "${USE_DOCKER}" == "true" ]]; then
  IPERF_CMD="docker run --rm --network host ${IPERF3_IMAGE} iperf3"
else
  IPERF_CMD="iperf3"
fi

echo "=== Starting iperf3 server ==="
echo "Bind: ${SERVER_IP}"
echo "Command: ${IPERF_CMD} -s -B ${SERVER_IP}"
echo ""

exec ${IPERF_CMD} -s -B "${SERVER_IP}"