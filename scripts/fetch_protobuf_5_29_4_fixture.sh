#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_ROOT="${1:-$ROOT_DIR/.targets}"
ARCHIVE_URL="https://files.pythonhosted.org/packages/source/p/protobuf/protobuf-5.29.4.tar.gz"
ARCHIVE_PATH="$TARGET_ROOT/protobuf-5.29.4.tar.gz"
EXTRACTED_DIR="$TARGET_ROOT/protobuf-5.29.4"

mkdir -p "$TARGET_ROOT"

if [[ ! -f "$ARCHIVE_PATH" ]]; then
  curl -L "$ARCHIVE_URL" -o "$ARCHIVE_PATH"
fi

if [[ ! -d "$EXTRACTED_DIR" ]]; then
  tar -xzf "$ARCHIVE_PATH" -C "$TARGET_ROOT"
fi

printf '%s\n' "$EXTRACTED_DIR"
