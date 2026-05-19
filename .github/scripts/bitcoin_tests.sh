#!/usr/bin/env bash
# Generate a balanced test matrix for the Bitcoin integration test workflow.
#
# Discovers all ignored tests in the stacks-node binary via cargo nextest,
# removes a hardcoded exclude list, then splits the remaining tests into
# MATRIX balanced partitions.
#
# Optional env vars:
#   MATRIX           - Number of partitions to split tests into (default: 2)
#   MAX_PER_MATRIX   - Maximum tests allowed per partition (default: 256)
#   NEXTEST_ARCHIVE  - Nextest archive to use (default: ~/test_archive.tar.zst)
#   TEST_TAG_CI_SKIP - Tag name used to exclude tests from CI (default: ci_skip)
#
# Outputs:
#   GITHUB_OUTPUT  - Path to the GitHub Actions output file (set by runner); prints to stderr if unset (via logging.sh)
set -euo pipefail

# Load logging functions from logging.sh for color and standardized output
# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/logging.sh"

## --- Configuration ----------------------------------------------------------
# Set number of matrices to use for tests. default is 2
matrix="${MATRIX:-2}"
# Set number of tests per matrix. default is 256
max_per_matrix="${MAX_PER_MATRIX:-256}"
# Set the nextest archive to use
nextest_archive="${NEXTEST_ARCHIVE:-${HOME}/test_archive.tar.zst}"
# Exclude tests tagged with a skip tag
ci_skip_tag="${TEST_TAG_CI_SKIP:-ci_skip}"

if ! [[ "$matrix" =~ ^[1-9][0-9]*$ ]]; then
    error "MATRIX must be a positive integer, got: ${matrix}"
    exit 1
fi

## ── Require bash 5+ (mapfile with -t flag behaviour) ────────────────────────
if [[ "${BASH_VERSINFO[0]}" -lt 5 ]]; then
    error "Bash version 5 or higher is required (found ${BASH_VERSION})"
    exit 1
fi

## ── Check for required binaries ─────────────────────────────────────────────
missing=0
for cmd in cargo comm grep jq sort wc; do
    if ! command -v "${cmd}" > /dev/null 2>&1; then
        error "Missing required command: $(hl "${cmd}")"
        missing=1
    fi
done
[[ "${missing}" -eq 1 ]] && exit 1

## --- List all ignored tests via nextest -------------------------------------
info "Listing ignored tests from nextest archive..."
cargo nextest list --archive-file "${nextest_archive}" -Tjson > nextest_output.json || {
    error "Error listing tests in $(hl ${nextest_archive})"
    exit 1
}

jq -c '
    .["rust-suites"]["stacks-node::bin/stacks-node"]["testcases"]
    | [to_entries[] | select(.value.ignored) | .key]
' nextest_output.json > ignored_tests.json

info "Ignored tests count: $(hl $(jq 'length' ignored_tests.json))"

## ── Build list of excluded tests --------------------------------------------
info "Building exclude list..."
cat << 'EOF' > raw_exclude.txt
# The following tests are excluded from CI runs. Some of these may be worth investigating adding back into the CI
tests::nakamoto_integrations::consensus_hash_event_dispatcher
tests::neon_integrations::atlas_integration_test
tests::neon_integrations::atlas_stress_integration_test
tests::neon_integrations::bitcoind_resubmission_test
tests::neon_integrations::block_replay_integration_test
tests::neon_integrations::deep_contract
tests::neon_integrations::filter_txs_by_origin
tests::neon_integrations::filter_txs_by_type
tests::neon_integrations::lockup_integration
tests::neon_integrations::most_recent_utxo_integration_test
tests::neon_integrations::run_with_custom_wallet
tests::neon_integrations::test_competing_miners_build_anchor_blocks_on_same_chain_without_rbf
tests::neon_integrations::test_one_miner_build_anchor_blocks_on_same_chain_without_rbf
tests::signer::v0::tenure_extend::tenure_extend_after_2_bad_commits
tests::stackerdb::test_stackerdb_event_observer
tests::stackerdb::test_stackerdb_load_store
# These mempool tests take a long time to run, and are meant to be run manually
tests::nakamoto_integrations::large_mempool_original_constant_fee
tests::nakamoto_integrations::large_mempool_original_random_fee
tests::nakamoto_integrations::large_mempool_next_constant_fee
tests::nakamoto_integrations::large_mempool_next_random_fee
tests::nakamoto_integrations::larger_mempool
tests::nakamoto_integrations::check_block_info_rewards
tests::signer::v0::larger_mempool
EOF

## ── Append tests tagged with ci_skip to the exclude list ────────────────────
ci_skip_regex=":t::(?:.*::)?${ci_skip_tag}::"
info "Excluding tests matching tag: $(hl "${ci_skip_tag}") (regex: $(hl "${ci_skip_regex}"))"
jq -r '.[]' ignored_tests.json | grep -P "${ci_skip_regex}" >> raw_exclude.txt || true

## ── Strip blank lines and comments, then convert to JSON array ──────────────
grep -v '^\s*$' raw_exclude.txt | grep -v '^\s*#' > clean_exclude.txt
jq -R . clean_exclude.txt | jq -s . > exclude.json
info "Excluded tests count: $(hl $(jq length exclude.json))"

## ── Filter out excluded tests -----------------------------------------------
info "Filtering excluded tests..."
jq -e 'type == "array"' ignored_tests.json > /dev/null
jq -e 'type == "array"' exclude.json > /dev/null

jq -r '.[]' ignored_tests.json | sort > ignored_sorted.txt
jq -r '.[]' exclude.json       | sort > exclude_sorted.txt

comm -23 ignored_sorted.txt exclude_sorted.txt > filtered.txt

total=$(wc -l < filtered.txt)
info "Final test count: $(hl ${total})"

## --- Validate capacity ------------------------------------------------------
max_total=$(( matrix * max_per_matrix ))
if (( total > max_total )); then
    error "${total} tests exceed the limit of ${max_total} (${matrix} partitions × ${max_per_matrix} tests each)"
    error "Increase MATRIX or MAX_PER_MATRIX to accommodate."
    exit 1
fi

## ── Split into $matrix balanced partitions ----------------------------------
info "Splitting $(hl ${total}) tests into $(hl ${matrix}) active partitions..."
mapfile -t tests < filtered.txt

base=$(( total / matrix ))
remainder=$(( total % matrix ))
offset=0

for (( i = 1; i <= matrix; i++ )); do
    # Distribute remainder one test at a time across the first partitions
    size=$(( base + ( i <= remainder ? 1 : 0 ) ))
    partition=$(printf '%s\n' "${tests[@]:$offset:$size}" | jq -R . | jq -s -c .)
    info "matrix${i}: $(hl ${size}) tests"
    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
        echo "matrix${i}=${partition}" >> "${GITHUB_OUTPUT}"
    else
        echo "matrix${i}=${partition}"
    fi
    offset=$(( offset + size ))
done
