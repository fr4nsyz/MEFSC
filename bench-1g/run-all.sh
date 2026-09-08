#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.env"

RUNS="${1:-5}"
MODE="${2:-tcp}"

if [[ "${USE_DOCKER}" == "true" ]]; then
  IPERF_CMD="docker run --rm --network host ${IPERF3_IMAGE} iperf3"
else
  IPERF_CMD="iperf3"
fi

echo "=== bench-1g multi-run ==="
echo "Mode: ${MODE}"
echo "Runs: ${RUNS}"
echo ""

RESULTS_FILE="/tmp/bench-1g-results-$(date +%s).jsonl"
THROUGHPUTS=()

for i in $(seq 1 "${RUNS}"); do
  echo "--- Run ${i}/${RUNS} ---"
  
  case "${MODE}" in
    tcp)
      OUTPUT=$(${IPERF_CMD} -c "${CLIENT_IP}" -B "${SERVER_IP}" -P "${PARALLEL_STREAMS}" -t "${DURATION_SEC}" -w "${TCP_WINDOW}" -J 2>&1)
      ;;
    bidir)
      OUTPUT=$(${IPERF_CMD} -c "${CLIENT_IP}" -B "${SERVER_IP}" -P "${PARALLEL_STREAMS}" -t "${DURATION_SEC}" -w "${TCP_WINDOW}" --bidir -J 2>&1)
      ;;
    udp)
      OUTPUT=$(${IPERF_CMD} -c "${CLIENT_IP}" -B "${SERVER_IP}" -u -b "950M" -t "${DURATION_SEC}" -J 2>&1)
      ;;
    *)
      echo "Unknown mode: ${MODE}"
      exit 1
      ;;
  esac
  
  echo "${OUTPUT}" | tee -a "${RESULTS_FILE}"
  
  # Extract throughput (sum_sent for TCP, sum for UDP/bidir)
  if [[ "${MODE}" == "udp" ]]; then
    TP=$(echo "${OUTPUT}" | grep -o '"bits_per_second":[0-9.]*' | tail -1 | cut -d: -f2)
  else
    TP=$(echo "${OUTPUT}" | grep -o '"sum_sent":{"bits_per_second":[0-9.]*' | head -1 | cut -d: -f3)
  fi
  
  if [[ -n "${TP}" ]]; then
    THROUGHPUTS+=("${TP}")
    echo "Throughput: $(echo "scale=2; ${TP}/1000000000" | bc) Gbps"
  fi
  
  sleep 2
done

echo ""
echo "=== Summary (${RUNS} runs) ==="
if [[ ${#THROUGHPUTS[@]} -gt 0 ]]; then
  # Calculate stats using awk
  printf '%s\n' "${THROUGHPUTS[@]}" | awk '
    {
      sum += $1
      if (NR == 1 || $1 < min) min = $1
      if ($1 > max) max = $1
      vals[NR] = $1
    }
    END {
      avg = sum / NR
      # sort for median/p99
      n = asort(vals)
      median = (n % 2 == 1) ? vals[int(n/2)+1] : (vals[n/2] + vals[n/2+1]) / 2
      p99_idx = int(n * 0.99) + 1
      p99 = vals[p99_idx]
      printf "Min:  %.2f Gbps\n", min/1e9
      printf "Max:  %.2f Gbps\n", max/1e9
      printf "Avg:  %.2f Gbps\n", avg/1e9
      printf "Median: %.2f Gbps\n", median/1e9
      printf "P99:  %.2f Gbps\n", p99/1e9
    }
  '
fi
echo ""
echo "Raw results: ${RESULTS_FILE}"