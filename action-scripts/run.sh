#!/usr/bin/env bash
set -uo pipefail
# Note: NOT -e — we capture nyx's exit code manually.

# ── Build the nyx command ────────────────────────────────────────────────────
FORMAT="${INPUT_FORMAT:-sarif}"
ARGS=("scan" "${INPUT_PATH:-.}" "--quiet" "--format" "$FORMAT")

if [[ -n "${INPUT_FAIL_ON:-}" ]]; then
  ARGS+=("--fail-on" "$INPUT_FAIL_ON")
fi

# Append raw user args (word-split is intentional here)
if [[ -n "${INPUT_ARGS:-}" ]]; then
  read -ra EXTRA <<< "$INPUT_ARGS"
  ARGS+=("${EXTRA[@]}")
fi

# ── Execute the scan ─────────────────────────────────────────────────────────
OUTDIR="${RUNNER_TEMP:-/tmp}"
SARIF_FILE=""
NYX_EXIT=0

echo "::group::nyx scan"
echo "Running: nyx ${ARGS[*]}"

case "$FORMAT" in
  sarif)
    SARIF_FILE="${OUTDIR}/nyx-results.sarif"
    nyx "${ARGS[@]}" > "$SARIF_FILE" || NYX_EXIT=$?
    ;;
  json)
    nyx "${ARGS[@]}" > "${OUTDIR}/nyx-results.json" || NYX_EXIT=$?
    ;;
  *)
    nyx "${ARGS[@]}" || NYX_EXIT=$?
    ;;
esac

echo "::endgroup::"

# ── Count findings ───────────────────────────────────────────────────────────
FINDING_COUNT="unknown"
case "$FORMAT" in
  sarif)
    if [[ -f "$SARIF_FILE" ]]; then
      # Count SARIF result entries by ruleId occurrences
      FINDING_COUNT="$(grep -c '"ruleId"' "$SARIF_FILE" 2>/dev/null || echo "0")"
    fi
    ;;
  json)
    if [[ -f "${OUTDIR}/nyx-results.json" ]]; then
      FINDING_COUNT="$(grep -c '"id"' "${OUTDIR}/nyx-results.json" 2>/dev/null || echo "0")"
    fi
    ;;
esac

# ── Set outputs ──────────────────────────────────────────────────────────────
echo "exit-code=${NYX_EXIT}" >> "$GITHUB_OUTPUT"
echo "finding-count=${FINDING_COUNT}" >> "$GITHUB_OUTPUT"
if [[ -n "$SARIF_FILE" ]]; then
  echo "sarif-file=${SARIF_FILE}" >> "$GITHUB_OUTPUT"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
if [[ "$NYX_EXIT" -eq 0 ]]; then
  echo "::notice::Nyx scan completed. Findings: ${FINDING_COUNT}"
else
  echo "::warning::Nyx scan found issues meeting threshold. Findings: ${FINDING_COUNT}"
fi

exit "$NYX_EXIT"
