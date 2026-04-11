#!/usr/bin/env bash
# Install sso-jwt into a WSL distribution.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/jgowdy/sso-jwt/main/scripts/install-wsl.sh | bash
#
# Or from a local checkout:
#   ./scripts/install-wsl.sh
#
# Prerequisites:
#   - Running inside WSL
#   - sso-jwt must be installed on the Windows host first (for the TPM bridge)
#   - gh CLI or curl with GitHub token for private repo access

set -euo pipefail

REPO="jgowdy/sso-jwt"
INSTALL_DIR="${HOME}/.local/bin"

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  TARGET="x86_64-unknown-linux-gnu" ;;
  aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
  *)
    echo "error: unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

# Detect WSL
if [ -z "${WSL_DISTRO_NAME:-}" ]; then
  echo "warning: WSL_DISTRO_NAME not set. This script is intended for WSL." >&2
  echo "         Continuing anyway (works on native Linux too)." >&2
fi

# Get latest release tag
echo "Fetching latest release..."
if command -v gh &>/dev/null; then
  TAG=$(gh release view --repo "$REPO" --json tagName --jq '.tagName')
else
  echo "error: gh CLI required. Install with: sudo apt install gh" >&2
  exit 1
fi

echo "Installing sso-jwt ${TAG} for ${TARGET}..."

ARCHIVE="sso-jwt-${TARGET}.tar.gz"

# Download
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

gh release download "$TAG" --repo "$REPO" --pattern "$ARCHIVE" --output "$TMPDIR/$ARCHIVE"

# Extract
tar xzf "$TMPDIR/$ARCHIVE" -C "$TMPDIR"

# Install
mkdir -p "$INSTALL_DIR"
install -m 755 "$TMPDIR/sso-jwt" "$INSTALL_DIR/sso-jwt"

echo "Installed sso-jwt to $INSTALL_DIR/sso-jwt"

# Check PATH
if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
  echo ""
  echo "Add to your shell profile:"
  echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
fi

# Check for TPM bridge on Windows host
BRIDGE_PATH="/mnt/c/Program Files/sso-jwt/sso-jwt-tpm-bridge.exe"
if [ -f "$BRIDGE_PATH" ]; then
  echo "TPM bridge found at: $BRIDGE_PATH"
else
  echo ""
  echo "warning: TPM bridge not found at expected path."
  echo "         Install sso-jwt on the Windows host first (MSI installer)."
  echo "         Expected: $BRIDGE_PATH"
fi

# Suggest shell integration
echo ""
echo "Add shell integration to your profile:"
echo "  echo 'eval \"\$(sso-jwt shell-init)\"' >> ~/.bashrc"
echo ""
echo "Done."
