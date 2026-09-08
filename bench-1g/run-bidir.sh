#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.env"

if [[ "${USE_DOCKER}" == "true" ]]; then
  IPERF_CMD="docker run --rm --network host ${IPERF3_IMAGE} iperf3"
else
  IPERF_CMD="iperf3"
fi

# Check iperf3 version supports --bidir
VERSION=$(${IPERF_CMD} --version 2>&1 | head -1)
echo "iperf3 version: ${VERSION}"

if ! ${IPERF_CMD} --help 2>&1 | grep -q -- '--bidir'; then
  echo "ERROR: This iperf3 version does not support --bidir (need >= 3.7)"
  exit 1
fi

echo "=== Running iperf3 bidirectional test ==="
echo "Target: ${CLIENT_IP}"
echo "Bind: ${SERVER_IP}"
echo "Streams: ${PARALLEL_STREAMS}"
echo "Duration: ${DURATION_SEC}s"
echo ""

exec ${IPERF_CMD} -c "${CLIENT_IP}" \
  -B "${SERVER_IP}" \
  -P "${PARALLEL_STREAMS}" \
  -t "${DURATION_SEC}" \
  -i "${REPORT_INTERVAL}" \
  -w "${TCP_WINDOW}" \
  --bidir \
  -J