#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.env"

if [[ "${USE_DOCKER}" == "true" ]]; then
  IPERF_CMD="docker run --rm --network host ${IPERF3_IMAGE} iperf3"
else
  IPERF_CMD="iperf3"
fi

echo "=== Running iperf3 client (TCP, multi-stream) ==="
echo "Target: ${CLIENT_IP}"
echo "Bind: ${SERVER_IP}"
echo "Streams: ${PARALLEL_STREAMS}"
echo "Duration: ${DURATION_SEC}s"
echo "Window: ${TCP_WINDOW}"
echo ""

exec ${IPERF_CMD} -c "${CLIENT_IP}" \
  -B "${SERVER_IP}" \
  -P "${PARALLEL_STREAMS}" \
  -t "${DURATION_SEC}" \
  -i "${REPORT_INTERVAL}" \
  -w "${TCP_WINDOW}" \
  -J