#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.env"

MEFSC_ROOT="/Users/fr4nsyz/vault/projects/MEFSC"
SERVER_BIN="${MEFSC_ROOT}/build/server"
CLIENT_BIN="${MEFSC_ROOT}/build/client_fs/client"
TEST_FILE="${MEFSC_ROOT}/test_100MB.bin"
STORAGE_USER="${MEFSC_ROOT}/build/MEF_S/henry"
SERVER_LOG="${SCRIPT_DIR}/server.log"
CLIENT_LOG="${SCRIPT_DIR}/client.log"

USERNAME="henry"
PASSWORD="swabber"
SERVER_PORT=8080

for b in "${SERVER_BIN}" "${CLIENT_BIN}"; do
  [[ -x "${b}" ]] || { echo "missing binary: ${b}"; exit 1; }
done
[[ -f "${TEST_FILE}" ]] || { echo "creating test file"; dd if=/dev/zero of="${TEST_FILE}" bs=1M count=100 status=progress; }
mkdir -p "${STORAGE_USER}"

SERVER_PID=""

cleanup() {
  kill -9 "${SERVER_PID}" 2>/dev/null || true
}
trap cleanup EXIT

start_server() {
  echo "[server] binding to 0.0.0.0:${SERVER_PORT}"
  ( cd "${MEFSC_ROOT}/build" && exec ./server ) < /dev/null > "${SERVER_LOG}" 2>&1 &
  SERVER_PID=$!
  sleep 2
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    echo "[server] failed to start (see ${SERVER_LOG})"; exit 1
  fi
  echo "[server] PID ${SERVER_PID}"
}

measure_upload() {
  local size_bytes
  size_bytes=$(stat -f%z "${TEST_FILE}")
  local size_mb=$((size_bytes / 1048576))

  echo "[upload] ${size_mb}MB -> ${CLIENT_IP}:${SERVER_PORT}"
  rm -f "${STORAGE_USER}/test_100MB.bin.enc"

  local start end elapsed_s throughput_mbps
  start=$(python3 -c "import time; print(time.time())")

  ( cd "${MEFSC_ROOT}" && \
    echo -e "${USERNAME}\n${PASSWORD}\n2\ntest_100MB.bin\nn" \
      | "${CLIENT_BIN}" "${CLIENT_IP}" "${SERVER_IP}" ) > "${CLIENT_LOG}" 2>&1

  end=$(python3 -c "import time; print(time.time())")
  elapsed_s=$(python3 -c "print(round(${end} - ${start}, 3))")
  throughput_mbps=$(python3 -c "print(round(${size_bytes} * 8 / ${elapsed_s} / 1000000, 2))")

  echo ""
  echo "=== UPLOAD RESULT ==="
  echo "  File:       ${size_mb} MB"
  echo "  Time:       ${elapsed_s}s"
  echo "  Throughput: ${throughput_mbps} Mbps"
}

measure_download() {
  local enc_file="${STORAGE_USER}/test_100MB.bin.enc"
  if [[ ! -f "${enc_file}" ]]; then
    echo "[download] no uploaded file found, run upload first"
    exit 1
  fi
  local size_bytes
  size_bytes=$(stat -f%z "${enc_file}")
  local size_mb=$((size_bytes / 1048576))

  echo "[download] ${size_mb}MB <- ${CLIENT_IP}:${SERVER_PORT}"
  rm -f "${MEFSC_ROOT}/test_100MB.bin"

  local start end elapsed_s throughput_mbps
  start=$(python3 -c "import time; print(time.time())")

  ( cd "${MEFSC_ROOT}" && \
    echo -e "${USERNAME}\n${PASSWORD}\n1\ntest_100MB.bin.enc\nn" \
      | "${CLIENT_BIN}" "${CLIENT_IP}" "${SERVER_IP}" ) > "${CLIENT_LOG}" 2>&1

  end=$(python3 -c "import time; print(time.time())")
  elapsed_s=$(python3 -c "print(round(${end} - ${start}, 3))")
  throughput_mbps=$(python3 -c "print(round(${size_bytes} * 8 / ${elapsed_s} / 1000000, 2))")

  echo ""
  echo "=== DOWNLOAD RESULT ==="
  echo "  File:       ${size_mb} MB"
  echo "  Time:       ${elapsed_s}s"
  echo "  Throughput: ${throughput_mbps} Mbps"
}

MODE="${1:-upload}"
start_server

case "${MODE}" in
  upload)   measure_upload ;;
  download) measure_download ;;
  both)     measure_upload; sleep 1; measure_download ;;
  *)        echo "usage: $0 {upload|download|both}"; exit 1 ;;
esac
