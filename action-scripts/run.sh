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
count_findings() {
  python3 -c "
import json, sys
try:
    data = json.load(open(sys.argv[1]))
    fmt = sys.argv[2]
    if fmt == 'sarif':
        runs = data.get('runs', [])
        print(len(runs[0].get('results', [])) if runs else 0)
    else:
        print(len(data) if isinstance(data, list) else 0)
except Exception:
    print(0)
" "$1" "$2" 2>/dev/null || echo "0"
}

FINDING_COUNT="unknown"
case "$FORMAT" in
  sarif)
    if [[ -f "$SARIF_FILE" ]]; then
      FINDING_COUNT="$(count_findings "$SARIF_FILE" sarif)"
    fi
    ;;
  json)
    if [[ -f "${OUTDIR}/nyx-results.json" ]]; then
      FINDING_COUNT="$(count_findings "${OUTDIR}/nyx-results.json" json)"
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
