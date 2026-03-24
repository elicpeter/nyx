#!/usr/bin/env bash
set -euo pipefail

REPO="elicpeter/nyx"
VERSION="${NYX_VERSION:-latest}"
INSTALL_DIR="${RUNNER_TOOL_CACHE:-/tmp}/nyx"

# ── Detect runner OS and architecture ─────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

case "${OS}-${ARCH}" in
  Linux-x86_64)        TARGET="x86_64-unknown-linux-gnu" ;;
  Linux-aarch64)       TARGET="aarch64-unknown-linux-gnu" ;;
  Darwin-x86_64)       TARGET="x86_64-apple-darwin" ;;
  Darwin-arm64)        TARGET="aarch64-apple-darwin" ;;
  *)
    echo "::error::Unsupported platform: ${OS} ${ARCH}"
    exit 1
    ;;
esac

# ── Resolve "latest" to an actual release tag ────────────────────────────────
if [[ "$VERSION" == "latest" ]]; then
  API_URL="https://api.github.com/repos/${REPO}/releases/latest"
  CURL_ARGS=(-fsSL)
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    CURL_ARGS+=(-H "Authorization: token ${GITHUB_TOKEN}")
  fi
  RELEASE_JSON="$(curl "${CURL_ARGS[@]}" "$API_URL")"
  VERSION="$(echo "$RELEASE_JSON" | grep -o '"tag_name":\s*"[^"]*"' | head -1 | cut -d'"' -f4)"
  if [[ -z "$VERSION" ]]; then
    echo "::error::Failed to resolve latest release tag from ${API_URL}"
    exit 1
  fi
  echo "Resolved latest version: ${VERSION}"
fi

# ── Download the release asset ───────────────────────────────────────────────
ASSET_NAME="nyx-${TARGET}.zip"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET_NAME}"

echo "Downloading nyx ${VERSION} for ${TARGET}..."
CURL_ARGS=(-fsSL -o /tmp/nyx.zip)
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  CURL_ARGS+=(-H "Authorization: token ${GITHUB_TOKEN}")
fi
curl "${CURL_ARGS[@]}" "$DOWNLOAD_URL"

# ── Extract and install ──────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR"
# The zip stores target/{TARGET}/release/nyx — use -j to flatten paths
unzip -o -j /tmp/nyx.zip "*/nyx" -d "$INSTALL_DIR"
chmod +x "${INSTALL_DIR}/nyx"
rm -f /tmp/nyx.zip

# ── Add to PATH for subsequent steps ─────────────────────────────────────────
echo "${INSTALL_DIR}" >> "$GITHUB_PATH"

# ── Verify and set output ────────────────────────────────────────────────────
INSTALLED_VERSION="$("${INSTALL_DIR}/nyx" --version 2>&1 | head -1 || echo "unknown")"
echo "nyx-version=${INSTALLED_VERSION}" >> "$GITHUB_OUTPUT"
echo "Installed nyx: ${INSTALLED_VERSION} (${TARGET})"
