#!/usr/bin/env bash
# Installs or updates opencyber (the nilparra-dev/opencyber fork of OpenCode) on Linux x64.
#
#   curl -fsSL https://raw.githubusercontent.com/nilparra-dev/opencyber/custom/script/fork-install.sh | bash
#
# Set OPENCYBER_VERSION (for example 2.0.18-cyber.1) to install a specific release.
set -euo pipefail

repo="nilparra-dev/opencyber"
dir="$HOME/.opencyber/bin"

if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
  echo "opencyber is only published for Linux x64 and Windows x64" >&2
  exit 1
fi

if [ -n "${OPENCYBER_VERSION:-}" ]; then
  tag="v${OPENCYBER_VERSION#v}"
else
  tag=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
fi

echo "Downloading opencyber $tag"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "https://github.com/$repo/releases/download/$tag/opencyber-linux-x64.tar.gz" | tar -xz -C "$tmp"
mkdir -p "$dir"
# Replacing through a rename keeps a running opencyber working until it exits.
mv -f "$tmp/opencyber" "$dir/opencyber"
chmod 755 "$dir/opencyber"

case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "Add $dir to your PATH, for example: echo 'export PATH=\"$dir:\$PATH\"' >> ~/.bashrc" ;;
esac

echo "Installed $("$dir/opencyber" --version) at $dir/opencyber"
