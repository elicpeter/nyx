#!/usr/bin/env bash
# Verify formatting, lint, and tests — no fixes applied. Mirrors CI.
#
# Covers (matches .github/workflows/ci.yml):
#   - cargo fmt --check
#   - cargo clippy -D warnings
#   - cargo test (summary only)
#   - frontend format:check, lint, typecheck, tests (summary only)
#
# Usage:  ./scripts/check.sh [--rust-only] [--frontend-only] [--bench]
#
# --bench additionally runs the CI benchmark gate (release build of the
# accuracy + perf regression tests; same commands the benchmark-gate CI job
# runs).  Opt-in because a release build is slow on a cold cache.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

DO_RUST=1
DO_FRONTEND=1
DO_BENCH=0
for arg in "$@"; do
    case "$arg" in
        --rust-only)      DO_FRONTEND=0 ;;
        --frontend-only)  DO_RUST=0 ;;
        --bench)          DO_BENCH=1 ;;
        -h|--help)
            sed -n '2,14p' "$0"; exit 0 ;;
        *) echo "unknown arg: $arg"; exit 2 ;;
    esac
done

if [[ -t 1 ]]; then
    BOLD=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; CYN=$'\033[36m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
    BOLD=''; RED=''; GRN=''; CYN=''; DIM=''; RST=''
fi

FRONTEND_DIR="$REPO_ROOT/frontend"
HAS_FRONTEND=0
[[ -f "$FRONTEND_DIR/package.json" ]] && HAS_FRONTEND=1

results=()
failed=0

# Execute a command inside frontend/ via a subshell — isolated cwd, no state leak.
in_frontend() {
    ( cd "$FRONTEND_DIR" && "$@" )
}

run_quiet() {
    local name="$1"; shift
    printf "${CYN}▶ %s${RST} ... " "$name"
    local log; log=$(mktemp -t nyx-check.XXXXXX)
    if "$@" >"$log" 2>&1; then
        printf "${GRN}PASS${RST}\n"
        results+=("$name|OK")
        rm -f "$log"
    else
        printf "${RED}FAIL${RST}\n"
        results+=("$name|FAIL")
        failed=1
        echo "${DIM}── last 40 lines ──${RST}"
        tail -n 40 "$log"
        echo "${DIM}── full log: $log ──${RST}"
    fi
}

if [[ $DO_RUST -eq 1 ]]; then
    run_quiet "cargo fmt --check"    cargo fmt --all -- --check
    run_quiet "cargo clippy"         cargo clippy --all-targets --all-features -- -D warnings
    run_quiet "cargo test"           cargo test --all-features --no-fail-fast
fi

if [[ $DO_BENCH -eq 1 ]]; then
    run_quiet "benchmark-gate accuracy (release)" \
        cargo test --release --all-features --test benchmark_test -- --ignored benchmark_evaluation
    run_quiet "benchmark-gate perf (release)" \
        env NYX_CI_BENCH=1 cargo test --release --all-features --test perf_tests
fi

if [[ $DO_FRONTEND -eq 1 && $HAS_FRONTEND -eq 1 ]]; then
    run_quiet "frontend format:check"  in_frontend npm run --silent format:check
    run_quiet "frontend lint"          in_frontend npm run --silent lint
    run_quiet "frontend typecheck"     in_frontend npm run --silent typecheck
    run_quiet "frontend tests (vitest)" in_frontend npm test --silent
fi

printf "\n${BOLD}Summary${RST}\n"
for r in "${results[@]}"; do
    name="${r%%|*}"; status="${r##*|}"
    if [[ "$status" == "OK" ]]; then
        printf "  ${GRN}✓${RST} %s\n" "$name"
    else
        printf "  ${RED}✗${RST} %s\n" "$name"
    fi
done

if [[ $failed -eq 0 ]]; then
    printf "\n${GRN}${BOLD}All checks passed.${RST}\n"
else
    printf "\n${RED}${BOLD}One or more checks failed.${RST}\n"
fi

exit $failed
