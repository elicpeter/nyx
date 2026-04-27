#!/bin/bash
# Overnight bughunt loop — runs sessions back-to-back until stopped.
#
# Usage:
#   ./scripts/bughunt-overnight.sh
#
# Stop (any of these works):
#   - Press Ctrl+C  (first press = graceful, second press = force)
#   - Press 'q'     (first press = graceful, second press = force)
#   - From another terminal:  touch /tmp/nyx-bughunt-stop
#
# "Graceful" = finish the current session, run a final summary session, exit.
# "Force"    = SIGTERM the current claude session and exit immediately.
#
# Per-session timeout is 2h. Output streams to terminal AND a per-night log
# file under nyx/logs/.

set -muo pipefail   # -m enables job control (puts each `&` in its own pgrp)

# ---- config ----
NYX_DIR="/Users/elipeter/nyx"
LOG_DIR="$NYX_DIR/logs"
CLAUDE_BIN="/Users/elipeter/.local/bin/claude"
LOCK_FILE="/tmp/nyx-bughunt-loop.lock"
STOP_FILE="/tmp/nyx-bughunt-stop"
SESSION_TIMEOUT_SECS=7200  # 2 hours

# ---- bootstrap ----
mkdir -p "$LOG_DIR"
NIGHT_TAG=$(date +%Y-%m-%d-%H%M)
NIGHT_LOG="$LOG_DIR/bughunt-overnight-$NIGHT_TAG.log"

if [ -e "$LOCK_FILE" ]; then
  PID=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
  if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
    echo "ERROR: another loop instance is already running (pid $PID)." >&2
    echo "       Stop it cleanly with: touch $STOP_FILE  (or Ctrl+C / 'q' in its terminal)" >&2
    exit 1
  fi
  rm -f "$LOCK_FILE"
fi
echo $$ > "$LOCK_FILE"

# Clear any stale stop flag from a prior run
rm -f "$STOP_FILE"

export HOME="/Users/elipeter"
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

cd "$NYX_DIR"

START_COMMIT=$(git rev-parse HEAD)
START_TIME=$(date '+%Y-%m-%d %H:%M:%S %Z')
START_EPOCH=$(date +%s)

# ---- prompts ----
SESSION_PROMPT='Read and execute the engine bughunt prompt at /Users/elipeter/nyx/docs/plans/bughunt-prompt.md. Follow it autonomously end-to-end, including Step 0.5 (read /Users/elipeter/oss/SESSION_LOG.md to pick the least-recently-targeted language), Step 5 (memory updates), and Step 6 (validate + update baseline). Do not commit. When done, append your one-line rotation entry to /Users/elipeter/oss/SESSION_LOG.md.'

SUMMARY_DATE=$(date +%Y-%m-%d)
SUMMARY_FILE="/Users/elipeter/oss/SESSION_NIGHT_$SUMMARY_DATE.md"

SUMMARY_PROMPT="Write an overnight bughunt roll-up summary for the night that started at $START_TIME (git start commit $START_COMMIT).

Sources to read:
- Every project_realrepo_*.md file in /Users/elipeter/.claude/projects/-Users-elipeter-nyx/memory/ that has a dated entry from tonight.
- All lines appended to /Users/elipeter/oss/SESSION_LOG.md after $START_TIME.
- Run 'cd /Users/elipeter/nyx && git diff --stat $START_COMMIT' for the file change summary.
- Run 'cd /Users/elipeter/nyx && git diff $START_COMMIT -- src/' for the engine code changes.
- Read $NIGHT_LOG for session boundaries, exit codes, and any aborts/timeouts.

Write a single roll-up at $SUMMARY_FILE with these sections:

1. Top-line: total sessions run, languages targeted, FPs fixed, TPs found, sessions aborted/timed-out.
2. By repo: each repo touched tonight with FPs fixed (rule_id @ file:line, root cause, fix at src/path:line, fix depth tag from the prompt's hierarchy: structural | classifier | label) and TPs found.
3. Engine code changes: grouped by module (src/ssa, src/taint, src/labels, src/auth_analysis, etc.) with one-line description per file of what changed.
4. Fixtures added: list paths under tests/benchmark/corpus with vuln_class.
5. Stop signals / open issues / follow-ups for tomorrow night.

Do not commit. Be concise — this is a morning briefing readable in under 2 minutes."

CLAUDE_FLAGS=(--permission-mode auto --model claude-opus-4-7 --effort xhigh --verbose --output-format stream-json --include-partial-messages -p)

# ---- interrupt handling: graceful (1st) -> force (2nd) ----

GRACEFUL_REQUESTED=0
CURRENT_CHILD_PID=""
STDIN_READER_PID=""

cleanup_on_exit() {
  [ -n "$STDIN_READER_PID" ] && kill "$STDIN_READER_PID" 2>/dev/null
  rm -f "$LOCK_FILE" "$STOP_FILE"
}

on_interrupt() {
  if [ "$GRACEFUL_REQUESTED" = "0" ]; then
    GRACEFUL_REQUESTED=1
    touch "$STOP_FILE"
    {
      echo ""
      echo "================================================================"
      echo "GRACEFUL STOP requested at $(date '+%H:%M:%S')."
      echo "  Will finish the current session, then run summary, then exit."
      echo "  Press Ctrl+C / 'q' AGAIN to force-stop immediately."
      echo "================================================================"
    } | tee -a "$NIGHT_LOG"
  else
    {
      echo ""
      echo "FORCE STOP at $(date '+%H:%M:%S'). Killing current claude session."
    } | tee -a "$NIGHT_LOG"
    if [ -n "$CURRENT_CHILD_PID" ]; then
      # Negative PID = kill the process group (job control put claude in its own pgrp)
      kill -TERM -"$CURRENT_CHILD_PID" 2>/dev/null
      sleep 1
      kill -KILL -"$CURRENT_CHILD_PID" 2>/dev/null
    fi
    cleanup_on_exit
    exit 130
  fi
}

trap on_interrupt INT TERM
trap cleanup_on_exit EXIT

# Background stdin reader: any 'q' or 'Q' keystroke triggers SIGINT to self.
# Reads from /dev/tty so it works even when stdin is otherwise redirected.
# If there's no tty (e.g., script run via nohup), the read fails and the
# subshell exits silently — Ctrl+C and the touch-file still work.
if [ -t 0 ] || [ -e /dev/tty ]; then
  (
    while IFS= read -r -n 1 ch < /dev/tty 2>/dev/null; do
      if [ "$ch" = "q" ] || [ "$ch" = "Q" ]; then
        kill -INT $$ 2>/dev/null
      fi
    done
  ) &
  STDIN_READER_PID=$!
fi

# ---- session runner with watchdog timeout ----

run_with_timeout() {
  local timeout_secs="$1"
  shift
  # Job control (set -m) puts this background job in its own process group.
  # That means Ctrl+C to the terminal does NOT propagate to claude.
  "$@" &
  CURRENT_CHILD_PID=$!

  # Watchdog: SIGTERM after timeout, SIGKILL 10s later if still alive.
  ( sleep "$timeout_secs" \
      && kill -TERM -"$CURRENT_CHILD_PID" 2>/dev/null \
      && sleep 10 \
      && kill -KILL -"$CURRENT_CHILD_PID" 2>/dev/null
  ) &
  local watchdog_pid=$!

  # Wait for child. If a signal interrupts us (graceful stop request), the
  # trap fires but we want to keep waiting for the current session to finish.
  local rc=0
  while true; do
    wait "$CURRENT_CHILD_PID" 2>/dev/null
    rc=$?
    if ! kill -0 "$CURRENT_CHILD_PID" 2>/dev/null; then
      break
    fi
  done

  kill "$watchdog_pid" 2>/dev/null
  wait "$watchdog_pid" 2>/dev/null
  CURRENT_CHILD_PID=""

  # rc > 128 = killed by signal; treat as timeout for our purposes
  if [ "$rc" -gt 128 ]; then
    return 124
  fi
  return "$rc"
}

run_session() {
  local label="$1"
  local prompt="$2"
  echo ""
  echo "===== $(date '+%Y-%m-%d %H:%M:%S %Z') — $label START ====="
  run_with_timeout "$SESSION_TIMEOUT_SECS" "$CLAUDE_BIN" "${CLAUDE_FLAGS[@]}" "$prompt"
  local rc=$?
  if [ "$rc" -eq 124 ]; then
    echo "===== $(date '+%Y-%m-%d %H:%M:%S %Z') — $label TIMED OUT after ${SESSION_TIMEOUT_SECS}s ====="
  else
    echo "===== $(date '+%Y-%m-%d %H:%M:%S %Z') — $label END (exit $rc) ====="
  fi
}

# ---- main ----

{
  echo "Bughunt overnight loop"
  echo "  Started:             $START_TIME"
  echo "  Start commit:        $START_COMMIT"
  echo "  Per-session timeout: $((SESSION_TIMEOUT_SECS / 3600))h"
  echo "  Stop:                Ctrl+C, 'q', or  touch $STOP_FILE"
  echo "                       (1st = graceful, 2nd = force)"
  echo "  Live log:            $NIGHT_LOG"
  echo "  Loop pid:            $$"
} | tee -a "$NIGHT_LOG"

session_num=0
while true; do
  if [ -e "$STOP_FILE" ]; then
    {
      echo ""
      echo "Stop flag detected at $(date '+%Y-%m-%d %H:%M:%S %Z') after $session_num session(s)."
      echo "Running summary..."
    } | tee -a "$NIGHT_LOG"
    break
  fi
  session_num=$((session_num + 1))
  run_session "session $session_num" "$SESSION_PROMPT" 2>&1 | tee -a "$NIGHT_LOG"
  sleep 5
done

run_session "summary" "$SUMMARY_PROMPT" 2>&1 | tee -a "$NIGHT_LOG"

{
  total_minutes=$(( ($(date +%s) - START_EPOCH) / 60 ))
  echo ""
  echo "Done."
  echo "  Total sessions:  $session_num"
  echo "  Total runtime:   ${total_minutes} min"
  echo "  Summary file:    $SUMMARY_FILE"
  echo "  Full log:        $NIGHT_LOG"
} | tee -a "$NIGHT_LOG"
