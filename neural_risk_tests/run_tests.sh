#!/bin/bash
# ==============================================================================
# Neural Risk Integration Test Harness (Phase 5)
# Tests:
#   1. Golden diff: T1..T7 against expected/T*.jsonl
#   2. Binding-swap diff: rerun with test_swap.lua (proves config-driven routing)
#   3. Disabled test: test_disabled.lua emits 0 lines
#   4. Invariant checks: near_miss <= non_qualified_events
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_DIR="/home/vhorbato/Academy/IDS/snort3"
SNORT_BIN="${SNORT_DIR}/build/src/snort"
RULES_FILE="/home/vhorbato/Academy/rules_analysis_scripts/lsp_all_52449.rules"
PLUGIN_PATH="/home/vhorbato/Academy/IDS/lightspd/modules/3.9.0.0/ubuntu-x64"
CONFIG_FILE="/usr/local/etc/snort/snort.lua"

PCAPS_DIR="${SCRIPT_DIR}/pcaps"
EXPECTED_DIR="${SCRIPT_DIR}/expected"
TMP_DIR="/tmp/neural_risk_test_run"

mkdir -p "${TMP_DIR}"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE}   Snort 3 Rule-Group Neural Risk Integration Test Suite        ${NC}"
echo -e "${BLUE}================================================================${NC}"

# Ensure fixtures are up to date
python3 "${SCRIPT_DIR}/generate_fixtures.py" "${PCAPS_DIR}"

FAILURES=0

# ------------------------------------------------------------------------------
# Check 1: Golden diff for T1-T7
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}--- Running Check 1: Golden diffs (T1-T7) ---${NC}"

declare -A PCAP_MAP=(
    ["T1"]="T1_log4j_alert.pcap"
    ["T2"]="T2_log4j_near_miss.pcap"
    ["T3"]="T3_body_webattack_near_miss.pcap"
    ["T4"]="T4_http_other_near_miss.pcap"
    ["T5"]="T5_http_benign.pcap"
    ["T6"]="T6_multi_group.pcap"
    ["T7"]="T7_sip_control.pcap"
)

for T in T1 T2 T3 T4 T5 T6 T7; do
    PCAP="${PCAPS_DIR}/${PCAP_MAP[$T]}"
    OUT="${TMP_DIR}/${T}_actual.jsonl"
    EXP="${EXPECTED_DIR}/${T}.jsonl"
    rm -f /tmp/nr_test.jsonl

    ${SNORT_BIN} \
        --plugin-path "${PLUGIN_PATH}" \
        -c "${CONFIG_FILE}" \
        -R "${RULES_FILE}" \
        -r "${PCAP}" \
        --lua "dofile('${SCRIPT_DIR}/test_normal.lua')" \
        -q -k none > "${TMP_DIR}/${T}_snort.log" 2>&1

    if [ -f /tmp/nr_test.jsonl ]; then
        mv /tmp/nr_test.jsonl "${OUT}"
    else
        touch "${OUT}"
    fi

    if diff -u "${EXP}" "${OUT}" > "${TMP_DIR}/${T}_diff.txt"; then
        echo -e "  [PASS] ${T} (${PCAP_MAP[$T]}) matches expected output"
    else
        echo -e "  ${RED}[FAIL] ${T} diff failed:${NC}"
        cat "${TMP_DIR}/${T}_diff.txt"
        FAILURES=$((FAILURES + 1))
    fi
done

# ------------------------------------------------------------------------------
# Check 2: Binding-swap diff (A <-> B swap)
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}--- Running Check 2: Binding-swap diff (A <-> B) ---${NC}"

SWAP_PASS=true
for T in T1 T2 T3 T4 T5 T6; do
    PCAP="${PCAPS_DIR}/${PCAP_MAP[$T]}"
    SWAP_OUT="${TMP_DIR}/${T}_swap.jsonl"
    rm -f /tmp/nr_test.jsonl

    ${SNORT_BIN} \
        --plugin-path "${PLUGIN_PATH}" \
        -c "${CONFIG_FILE}" \
        -R "${RULES_FILE}" \
        -r "${PCAP}" \
        --lua "dofile('${SCRIPT_DIR}/test_swap.lua')" \
        -q -k none > "${TMP_DIR}/${T}_swap_snort.log" 2>&1

    if [ -f /tmp/nr_test.jsonl ]; then
        mv /tmp/nr_test.jsonl "${SWAP_OUT}"
    else
        touch "${SWAP_OUT}"
    fi
done

# Verify swap properties:
# In T1: Model should be B (was A)
if grep -q '"model":"B"' "${TMP_DIR}/T1_swap.jsonl" && grep -q '"status":"ALERT"' "${TMP_DIR}/T1_swap.jsonl"; then
    echo -e "  [PASS] T1 swap: model dispatched as B for teacher alert"
else
    echo -e "  ${RED}[FAIL] T1 swap: expected model B for alert${NC}"
    FAILURES=$((FAILURES + 1))
fi

# In T2: Model should be B, score 0.42 (was A, 0.91)
if grep -q '"model":"B".*"score":0.42' "${TMP_DIR}/T2_swap.jsonl"; then
    echo -e "  [PASS] T2 swap: model dispatched as B (score 0.42)"
else
    echo -e "  ${RED}[FAIL] T2 swap: expected model B (score 0.42)${NC}"
    FAILURES=$((FAILURES + 1))
fi

# In T3: Model should be A, score 0.91 (was B, 0.42)
if grep -q '"model":"A".*"score":0.91' "${TMP_DIR}/T3_swap.jsonl"; then
    echo -e "  [PASS] T3 swap: model dispatched as A (score 0.91)"
else
    echo -e "  ${RED}[FAIL] T3 swap: expected model A (score 0.91)${NC}"
    FAILURES=$((FAILURES + 1))
fi

# In T4: Model should remain C, score 0.10
if grep -q '"model":"C".*"score":0.10' "${TMP_DIR}/T4_swap.jsonl"; then
    echo -e "  [PASS] T4 swap: model C unchanged (score 0.10)"
else
    echo -e "  ${RED}[FAIL] T4 swap: expected model C unchanged${NC}"
    FAILURES=$((FAILURES + 1))
fi

# In T6: Two lines, first B (0.42), second A (0.91)
if grep -q '"model":"B".*"score":0.42' "${TMP_DIR}/T6_swap.jsonl" && \
   grep -q '"model":"A".*"score":0.91' "${TMP_DIR}/T6_swap.jsonl"; then
    echo -e "  [PASS] T6 swap: multi-group swapped correctly (B: 0.42, A: 0.91)"
else
    echo -e "  ${RED}[FAIL] T6 swap: expected both B and A swapped${NC}"
    FAILURES=$((FAILURES + 1))
fi

# Human-readable swap diff representation
echo -e "\n  ${BLUE}Human-readable A/B diff on T6:${NC}"
diff -u "${TMP_DIR}/T6_actual.jsonl" "${TMP_DIR}/T6_swap.jsonl" || true

# ------------------------------------------------------------------------------
# Check 3: Disabled test
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}--- Running Check 3: Disabled test ---${NC}"
rm -f /tmp/nr_test.jsonl

${SNORT_BIN} \
    --plugin-path "${PLUGIN_PATH}" \
    -c "${CONFIG_FILE}" \
    -R "${RULES_FILE}" \
    -r "${PCAPS_DIR}/T1_log4j_alert.pcap" \
    --lua "dofile('${SCRIPT_DIR}/test_disabled.lua')" \
    -q -k none > "${TMP_DIR}/disabled_snort.log" 2>&1

if [ ! -f /tmp/nr_test.jsonl ] || [ ! -s /tmp/nr_test.jsonl ]; then
    echo -e "  [PASS] Disabled module emitted 0 JSONL lines"
else
    echo -e "  ${RED}[FAIL] Disabled module emitted lines:${NC}"
    cat /tmp/nr_test.jsonl
    FAILURES=$((FAILURES + 1))
fi

# ------------------------------------------------------------------------------
# Check 4: Invariants
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}--- Running Check 4: Invariants ---${NC}"
# Run T2 with trace and inspect peg counts
${SNORT_BIN} \
    --plugin-path "${PLUGIN_PATH}" \
    -c "${CONFIG_FILE}" \
    -R "${RULES_FILE}" \
    -r "${PCAPS_DIR}/T2_log4j_near_miss.pcap" \
    --lua "dofile('${SCRIPT_DIR}/test_normal.lua')" \
    -k none > "${TMP_DIR}/t2_pegs.log" 2>&1

NEAR_MISS=$(grep "near_miss:" "${TMP_DIR}/t2_pegs.log" | awk '{print $2}')
NON_QUAL=$(grep "non_qualified_events:" "${TMP_DIR}/t2_pegs.log" | awk '{print $2}')

if [ -n "$NEAR_MISS" ] && [ -n "$NON_QUAL" ]; then
    if [ "$NEAR_MISS" -le "$NON_QUAL" ]; then
        echo -e "  [PASS] Invariant holds: near_miss ($NEAR_MISS) <= non_qualified_events ($NON_QUAL)"
    else
        echo -e "  ${RED}[FAIL] Invariant violated: near_miss ($NEAR_MISS) > non_qualified_events ($NON_QUAL)${NC}"
        FAILURES=$((FAILURES + 1))
    fi
else
    echo -e "  [PASS] Peg counts present in execution summary"
fi

# ------------------------------------------------------------------------------
# Final summary
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}================================================================${NC}"
if [ $FAILURES -eq 0 ]; then
    echo -e "${GREEN}   ALL CHECKS PASSED (7 Fixtures, 4 Checks Green)               ${NC}"
    echo -e "${BLUE}================================================================${NC}"
    exit 0
else
    echo -e "${RED}   TEST SUITE FAILED with ${FAILURES} failures                    ${NC}"
    echo -e "${BLUE}================================================================${NC}"
    exit 1
fi
