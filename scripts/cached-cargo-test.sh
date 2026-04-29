#!/bin/bash
# Cached cargo test wrapper.
#
# Returns the cached output of a prior identical `cargo test` run when
# the source tree hasn't changed. Concurrent invocations with the same
# cache key serialize via a mkdir-based lock — only one cargo run
# actually executes; later callers wait, then return the cached result
# instantly.
#
# Usage:
#   scripts/cached-cargo-test.sh [cargo-test-args...]
#
# Bypass:
#   FORCE_CARGO=1 scripts/cached-cargo-test.sh ...
#
# When to use: full-suite invocations like
#   scripts/cached-cargo-test.sh --lib
#   scripts/cached-cargo-test.sh --tests
#   scripts/cached-cargo-test.sh --test benchmark_test benchmark_evaluation -- --ignored --nocapture
#
# When NOT to use: narrow per-test runs like
#   cargo test --test integration_tests rust_web_app
#   cargo test some_function_name
# Those are fast on their own and would just clutter the cache.

set -uo pipefail

NYX_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CACHE_DIR="${NYX_CARGO_CACHE_DIR:-/tmp/nyx-cargo-cache}"
LOCK_TIMEOUT_SECS=7200   # 2h max wait for a concurrent leader
POLL_INTERVAL_SECS=1

mkdir -p "$CACHE_DIR"
cd "$NYX_DIR"

# ---- portable sha256 ----

sha256_cmd() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$@"
  else
    # macOS ships `shasum`; -a 256 selects sha256 and outputs the same
    # `<hash>  <file>` format as sha256sum.
    shasum -a 256 "$@"
  fi
}

# ---- compute cache key ----

# Hash everything that could affect cargo-test outcomes. Filename of each
# input is included in the per-file sha256 line, so renames + additions +
# deletions all change the rolled-up hash. The [ -f ] filter drops
# deleted-but-still-indexed files so we don't error out on them.
compute_source_hash() {
  {
    git ls-files src tests benches 2>/dev/null
    git ls-files --others --exclude-standard src tests benches 2>/dev/null
    for f in Cargo.toml Cargo.lock build.rs rust-toolchain rust-toolchain.toml; do
      [ -f "$f" ] && echo "$f"
    done
  } | sort -u | while IFS= read -r f; do
    [ -f "$f" ] && sha256_cmd "$f"
  done | sha256_cmd | awk '{print $1}'
}

# Hash the args verbatim. -separating with NUL bytes so "--lib" and
# "--li b" hash differently.
compute_args_hash() {
  if [ "$#" -eq 0 ]; then
    printf '' | sha256_cmd | awk '{print $1}'
  else
    printf '%s\0' "$@" | sha256_cmd | awk '{print $1}'
  fi
}

# Hash env vars that can change build/test outcomes.
compute_env_hash() {
  env | grep -E '^(RUST|CARGO|NYX)_' | LC_ALL=C sort \
    | sha256_cmd | awk '{print $1}'
}

SOURCE_HASH=$(compute_source_hash)
ARGS_HASH=$(compute_args_hash "$@")
ENV_HASH=$(compute_env_hash)

KEY="${SOURCE_HASH:0:16}-${ARGS_HASH:0:8}-${ENV_HASH:0:8}"
LOG_FILE="$CACHE_DIR/$KEY.log"
RC_FILE="$CACHE_DIR/$KEY.rc"
LOCK_DIR="$CACHE_DIR/$KEY.lock.d"

# ---- bypass ----
if [ "${FORCE_CARGO:-0}" != "0" ]; then
  echo "[cached-cargo-test] FORCE_CARGO=1 — bypassing cache" >&2
  exec cargo test "$@"
fi

# ---- fast path: cache hit, no lock needed ----
if [ -f "$LOG_FILE" ] && [ -f "$RC_FILE" ]; then
  RC=$(cat "$RC_FILE")
  echo "[cached-cargo-test] cache hit (key $KEY, rc $RC) — source unchanged since prior run" >&2
  cat "$LOG_FILE"
  exit "$RC"
fi

# ---- slow path: acquire lock, double-check, run if leader ----

attempts=0
while true; do
  if mkdir "$LOCK_DIR" 2>/dev/null; then
    echo "$$" > "$LOCK_DIR/pid"
    break
  fi
  # Stale-lock detection
  if [ -f "$LOCK_DIR/pid" ]; then
    OLD_PID=$(cat "$LOCK_DIR/pid" 2>/dev/null || echo "")
    if [ -n "$OLD_PID" ] && ! kill -0 "$OLD_PID" 2>/dev/null; then
      echo "[cached-cargo-test] reaping stale lock from dead pid $OLD_PID" >&2
      rm -rf "$LOCK_DIR" 2>/dev/null
      continue
    fi
  fi
  if [ "$attempts" -eq 0 ]; then
    echo "[cached-cargo-test] another invocation is running this same test set; waiting..." >&2
  fi
  attempts=$((attempts + 1))
  if [ "$attempts" -gt "$LOCK_TIMEOUT_SECS" ]; then
    echo "[cached-cargo-test] gave up waiting for lock after ${LOCK_TIMEOUT_SECS}s" >&2
    exit 1
  fi
  sleep "$POLL_INTERVAL_SECS"
done

# Always release the lock on exit, even on failure
trap 'rm -rf "$LOCK_DIR" 2>/dev/null' EXIT

# Double-check: the leader may have populated the cache while we waited.
if [ -f "$LOG_FILE" ] && [ -f "$RC_FILE" ]; then
  RC=$(cat "$RC_FILE")
  echo "[cached-cargo-test] cache hit after waiting (concurrent leader populated cache, rc $RC)" >&2
  cat "$LOG_FILE"
  exit "$RC"
fi

# We're the leader — actually run cargo.
echo "[cached-cargo-test] cache miss (key $KEY) — running cargo test $*" >&2
cargo test "$@" 2>&1 | tee "$LOG_FILE"
RC="${PIPESTATUS[0]}"
echo "$RC" > "$RC_FILE"
exit "$RC"
