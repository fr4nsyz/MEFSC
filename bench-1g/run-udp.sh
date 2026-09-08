#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.env"

if [[ "${USE_DOCKER}" == "true" ]]; then
  IPERF_CMD="docker run --rm --network host ${IPERF3_IMAGE} iperf3"
else
  IPERF_CMD="iperf3"
fi

# UDP target bandwidth (slightly under 1Gbps to avoid excessive loss)
UDP_BANDWIDTH="950M"

echo "=== Running iperf3 UDP test ==="
echo "Target: ${CLIENT_IP}"
echo "Bind: ${SERVER_IP}"
echo "Target bandwidth: ${UDP_BANDWIDTH}"
echo "Duration: ${DURATION_SEC}s"
echo ""

exec ${IPERF_CMD} -c "${CLIENT_IP}" \
  -B "${SERVER_IP}" \
  -u \
  -b "${UDP_BANDWIDTH}" \
  -t "${DURATION_SEC}" \
  -i "${REPORT_INTERVAL}" \
  -J