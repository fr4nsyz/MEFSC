#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.env"

echo "=== bench-1g teardown ==="

echo "Flushing pf dummynet anchor..."
pfctl -a dummynet -F all 2>/dev/null || true
pfctl -d 2>/dev/null || true

echo "Flushing dummynet..."
dnctl -f flush 2>/dev/null || true

echo "Destroying bridge ${BRIDGE_NAME}..."
ifconfig "${BRIDGE_NAME}" destroy 2>/dev/null || true

echo "=== Teardown complete ==="