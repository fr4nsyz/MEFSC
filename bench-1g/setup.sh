#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.env"

PF_ANCHOR="/tmp/pf.bench"

echo "=== bench-1g setup ==="

# 1. Bridge
if ! ifconfig "${BRIDGE_NAME}" >/dev/null 2>&1; then
  echo "Creating bridge..."
  CREATED=$(ifconfig bridge create)
  if [[ "${CREATED}" != "${BRIDGE_NAME}" ]]; then
    echo "NOTE: created ${CREATED} (want ${BRIDGE_NAME}), using ${CREATED}"
    BRIDGE_NAME="${CREATED}"
  fi
fi
ifconfig "${BRIDGE_NAME}" inet "${SERVER_IP}/32" alias 2>/dev/null || true
ifconfig "${BRIDGE_NAME}" inet "${CLIENT_IP}/32" alias 2>/dev/null || true
ifconfig "${BRIDGE_NAME}" up
echo "Bridge: $(ifconfig ${BRIDGE_NAME} | head -1)"

# 2. dummynet pipe (macOS: bw only supports K/M units; delay rounds to 10ms tick -> omitted)
echo "Configuring pipe ${PIPE_NUM}..."
dnctl pipe "${PIPE_NUM}" config \
  bw "${BANDWIDTH}" \
  queue "${QUEUE_SLOTS}" \
  plr "${PLR}"

# 3. pf rules (anchor "dummynet" is the special anchor macOS PF consults)
#    traffic between local IPs traverses lo0; "in" rules shape at the receive side
cat > "${PF_ANCHOR}" <<EOF
dummynet in quick from ${SERVER_IP} to ${CLIENT_IP} pipe ${PIPE_NUM}
dummynet in quick from ${CLIENT_IP} to ${SERVER_IP} pipe ${PIPE_NUM}
EOF

# 4. load into the special dummynet anchor, then enable pf
pfctl -a dummynet -f "${PF_ANCHOR}"
pfctl -E 2>/dev/null || true

# 5. verify
echo ""
echo "=== Pipe ==="
dnctl show pipe "${PIPE_NUM}"
echo ""
echo "=== PF rules ==="
pfctl -a dummynet -s rules 2>/dev/null || echo "(could not read rules)"
echo ""
echo "=== Done ==="
echo "Run server:  ./run-server.sh"
echo "Run client:  ./run-client.sh"
echo "Teardown:    sudo ./teardown.sh"
