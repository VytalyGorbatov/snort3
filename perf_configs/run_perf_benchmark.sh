#!/usr/bin/env bash
# ==============================================================================
# Snort 3 Rule-Group Neural Risk Benchmark Runner
#
# USAGE:
#   ./run_perf_benchmark.sh [--run] [--pcap <path>] [--threads <1|4|8>] [--iter <n>]
#
# NOTE:
#   By default, this script runs in DRY-RUN mode to show the commands and checks
#   without conducting actual performance runs. Pass --run to execute benchmarks.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Default paths
SNORT_BIN="${SNORT_BIN:-${SNORT_DIR}/build/src/snort}"
PLUGIN_PATH="${PLUGIN_PATH:-/home/vhorbato/Academy/IDS/lightspd/modules/3.9.0.0/ubuntu-x64}"
BASE_CONFIG="${BASE_CONFIG:-/usr/local/etc/snort/snort.lua}"
RULES_FILE="${RULES_FILE:-/home/vhorbato/Academy/rules_analysis_scripts/lsp_all_52449.rules}"

# Benchmark parameters
DEFAULT_PCAP="/home/vhorbato/Academy/http-lab/shared/pcaps/benign_50k.pcap"
PCAP="${1:-$DEFAULT_PCAP}"
THREADS="1"
ITERATIONS="3"
DRY_RUN="true"
OUTPUT_DIR="${SCRIPT_DIR}/results"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --run)
            DRY_RUN="false"
            shift
            ;;
        --pcap)
            PCAP="$2"
            shift 2
            ;;
        --threads)
            THREADS="$2"
            shift 2
            ;;
        --iter)
            ITERATIONS="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--run] [--pcap <file.pcap>] [--threads <1|4|8>] [--iter <N>]"
            exit 0
            ;;
        *)
            if [[ -f "$1" ]]; then
                PCAP="$1"
            fi
            shift
            ;;
    esac
done

VARIANTS=(
    "baseline:${SCRIPT_DIR}/perf_baseline.lua"
    "disabled:${SCRIPT_DIR}/perf_disabled.lua"
    "active_nolog:${SCRIPT_DIR}/perf_active_nolog.lua"
    "active_logged:${SCRIPT_DIR}/perf_active_logged.lua"
    "enterprise_huge:${SCRIPT_DIR}/perf_enterprise_huge.lua"
)

echo "================================================================================"
echo " Snort 3 Neural Risk Performance Benchmark Matrix"
echo "================================================================================"
echo " Snort Binary:  ${SNORT_BIN}"
echo " PCAP File:     ${PCAP}"
echo " Rules File:    ${RULES_FILE}"
echo " Threads (-z):  ${THREADS}"
echo " Iterations:    ${ITERATIONS}"
echo " Mode:          $([ "${DRY_RUN}" = "true" ] && echo "DRY-RUN (Inspect Only)" || echo "LIVE EXECUTION")"
echo "================================================================================"

if [ "${DRY_RUN}" = "true" ]; then
    echo -e "\n[DRY RUN] Commands that will be executed for each variant (pass --run to execute):\n"
    for item in "${VARIANTS[@]}"; do
        NAME="${item%%:*}"
        LUA_CONF="${item#*:}"
        echo "# --- Variant: ${NAME} (${LUA_CONF}) ---"
        echo "/usr/bin/time -v ${SNORT_BIN} \\"
        echo "    --plugin-path \"${PLUGIN_PATH}\" \\"
        echo "    -c \"${BASE_CONFIG}\" \\"
        echo "    --lua \"dofile('${LUA_CONF}')\" \\"
        echo "    -R \"${RULES_FILE}\" \\"
        echo "    -r \"${PCAP}\" \\"
        echo "    -z \"${THREADS}\" \\"
        echo "    -k none -q --dirty-pig"
        echo ""
    done
    echo "To run actual benchmarks, execute: $0 --run --pcap \"${PCAP}\" --threads ${THREADS} --iter ${ITERATIONS}"
    exit 0
fi

mkdir -p "${OUTPUT_DIR}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
CSV_OUT="${OUTPUT_DIR}/perf_results_${TIMESTAMP}_z${THREADS}.csv"
echo "variant,run,runtime_sec,pkts_per_sec,mbits_per_sec,user_cpu_sec,sys_cpu_sec,max_rss_kb,near_miss_pegs,alerts_seen_pegs" > "${CSV_OUT}"

for item in "${VARIANTS[@]}"; do
    NAME="${item%%:*}"
    LUA_CONF="${item#*:}"

    echo -e "\n>>> Testing Variant: ${NAME} (${ITERATIONS} runs)..."

    for i in $(seq 1 "${ITERATIONS}"); do
        LOG_FILE="${OUTPUT_DIR}/${NAME}_run${i}.log"
        TIME_FILE="${OUTPUT_DIR}/${NAME}_run${i}.time"

        echo -n "  Run ${i}/${ITERATIONS} ... "

        /usr/bin/time -v -o "${TIME_FILE}" \
        "${SNORT_BIN}" \
            --plugin-path "${PLUGIN_PATH}" \
            -c "${BASE_CONFIG}" \
            --lua "dofile('${LUA_CONF}')" \
            -R "${RULES_FILE}" \
            -r "${PCAP}" \
            -z "${THREADS}" \
            -k none --dirty-pig > "${LOG_FILE}" 2>&1

        # Extract metrics
        RUNTIME=$(grep "seconds:" "${LOG_FILE}" | awk '{print $2}' || echo "0")
        PKTS_SEC=$(grep "pkts/sec:" "${LOG_FILE}" | awk '{print $2}' || echo "0")
        MBITS_SEC=$(grep "Mbits/sec:" "${LOG_FILE}" | awk '{print $2}' || echo "0")
        USER_CPU=$(grep "User time (seconds):" "${TIME_FILE}" | awk '{print $4}' || echo "0")
        SYS_CPU=$(grep "System time (seconds):" "${TIME_FILE}" | awk '{print $4}' || echo "0")
        MAX_RSS=$(grep "Maximum resident set size (kbytes):" "${TIME_FILE}" | awk '{print $6}' || echo "0")
        NEAR_MISS=$(grep "near_miss:" "${LOG_FILE}" | awk '{print $2}' || echo "0")
        ALERTS_SEEN=$(grep "alerts_seen:" "${LOG_FILE}" | awk '{print $2}' || echo "0")

        echo "Time: ${RUNTIME}s | Throughput: ${MBITS_SEC} Mbits/s | ${PKTS_SEC} pkts/s | MaxRSS: ${MAX_RSS} KB"
        echo "${NAME},${i},${RUNTIME},${PKTS_SEC},${MBITS_SEC},${USER_CPU},${SYS_CPU},${MAX_RSS},${NEAR_MISS},${ALERTS_SEEN}" >> "${CSV_OUT}"
    done
done

echo -e "\n================================================================================"
echo " Benchmarking Complete! Results saved to:"
echo " ${CSV_OUT}"
echo "================================================================================"
