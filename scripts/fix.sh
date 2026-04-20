#!/usr/bin/env bash
# Fix formatting, apply lint auto-fixes, then run tests with a pass/fail summary.
#
# Covers:
#   - cargo clippy --fix  (Rust lint auto-fix)
#   - cargo fmt            (Rust formatter)
#   - eslint --fix         (frontend lint auto-fix)
#   - prettier --write     (frontend formatter)
#   - cargo test           (summary only)
#   - frontend typecheck + tests (summary only)
#
# Usage:  ./scripts/fix.sh [--no-tests] [--rust-only] [--frontend-only]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# ── flags ────────────────────────────────────────────────────────────────────
RUN_TESTS=1
DO_RUST=1
DO_FRONTEND=1
for arg in "$@"; do
    case "$arg" in
        --no-tests)       RUN_TESTS=0 ;;
        --rust-only)      DO_FRONTEND=0 ;;
        --frontend-only)  DO_RUST=0 ;;
        -h|--help)
            sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "unknown arg: $arg"; exit 2 ;;
    esac
done

# ── colors (disabled when not a TTY) ─────────────────────────────────────────
if [[ -t 1 ]]; then
    BOLD=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; CYN=$'\033[36m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
    BOLD=''; RED=''; GRN=''; YEL=''; CYN=''; DIM=''; RST=''
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

# Run a step with streamed output (good for fixers — you may want to see what changed).
run_loud() {
    local name="$1"; shift
    printf "\n${BOLD}${CYN}▶ %s${RST}\n" "$name"
    if "$@"; then
        results+=("$name|OK")
    else
        results+=("$name|FAIL")
        failed=1
    fi
}

# Run a step quietly; only show output on failure (good for tests — we want pass/fail).
run_quiet() {
    local name="$1"; shift
    printf "${CYN}▶ %s${RST} ${DIM}(quiet)${RST} ... " "$name"
    local log; log=$(mktemp -t nyx-fix.XXXXXX)
    if "$@" >"$log" 2>&1; then
        printf "${GRN}PASS${RST}\n"
        results+=("$name|OK")
        rm -f "$log"
    else
        printf "${RED}FAIL${RST}\n"
        results+=("$name|FAIL")
        failed=1
        echo "${DIM}── last 40 lines of output ──${RST}"
        tail -n 40 "$log"
        echo "${DIM}── full log: $log ──${RST}"
    fi
}

# ── fixers ───────────────────────────────────────────────────────────────────
if [[ $DO_RUST -eq 1 ]]; then
    # Clippy --fix first; fmt afterward to clean up any introduced style drift.
    run_loud "cargo clippy --fix" \
        cargo clippy --all-targets --all-features --fix --allow-dirty --allow-staged -- -D warnings
    run_loud "cargo fmt" \
        cargo fmt --all
fi

if [[ $DO_FRONTEND -eq 1 && $HAS_FRONTEND -eq 1 ]]; then
    # eslint --fix first; prettier afterward so formatting wins any conflicts.
    run_loud "eslint --fix (frontend)" \
        in_frontend npm run --silent lint -- --fix
    run_loud "prettier --write (frontend)" \
        in_frontend npm run --silent format
fi

# ── verifiers (summary only) ─────────────────────────────────────────────────
if [[ $RUN_TESTS -eq 1 ]]; then
    if [[ $DO_RUST -eq 1 ]]; then
        run_quiet "cargo test" \
            cargo test --all-features --no-fail-fast
    fi
    if [[ $DO_FRONTEND -eq 1 && $HAS_FRONTEND -eq 1 ]]; then
        run_quiet "frontend typecheck" \
            in_frontend npm run --silent typecheck
        run_quiet "frontend tests (vitest)" \
            in_frontend npm test --silent
    fi
fi

# ── summary ──────────────────────────────────────────────────────────────────
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
    printf "\n${GRN}${BOLD}All steps passed.${RST}\n"
else
    printf "\n${RED}${BOLD}One or more steps failed.${RST}\n"
fi

exit $failed
