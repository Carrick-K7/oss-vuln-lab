#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_ROOT="${1:-$ROOT_DIR/.targets}"
RUNS_DIR="${OVD_RUNS_DIR:-$ROOT_DIR/.ovd_runs}"
IMPACT_REPO="$TARGET_ROOT/protobuf-cve-2025-4565-git"
MANIFEST="$ROOT_DIR/examples/impact/protobuf-cve-2025-4565.json"
RUNTIME_MANIFEST="$TARGET_ROOT/protobuf-cve-2025-4565-impact.json"

mkdir -p "$TARGET_ROOT"

fetch_release() {
  local version="$1"
  local sha256="$2"
  local archive="$TARGET_ROOT/protobuf-$version.tar.gz"
  local extracted="$TARGET_ROOT/protobuf-$version"
  local url="https://files.pythonhosted.org/packages/source/p/protobuf/protobuf-$version.tar.gz"

  if [[ ! -f "$archive" ]]; then
    curl -L "$url" -o "$archive"
  fi

  printf '%s  %s\n' "$sha256" "$archive" | sha256sum -c -

  if [[ ! -d "$extracted" ]]; then
    tar -xzf "$archive" -C "$TARGET_ROOT"
  fi
}

import_release() {
  local version="$1"
  local extracted="$TARGET_ROOT/protobuf-$version"

  rsync -a --delete --exclude .git "$extracted"/ "$IMPACT_REPO"/
  git -C "$IMPACT_REPO" add -A
  git -C "$IMPACT_REPO" commit -m "Import protobuf $version"
  git -C "$IMPACT_REPO" tag "v$version"
}

fetch_release "5.29.4" "4f1dfcd7997b31ef8f53ec82781ff434a28bf71d9102ddde14d076adcfc78c99"
fetch_release "5.29.5" "bc1463bafd4b0929216c35f437a8e28731a2b7fe3d98bb77a600efced5a15c84"

rm -rf "$IMPACT_REPO"
mkdir -p "$IMPACT_REPO"
git -C "$IMPACT_REPO" init
git -C "$IMPACT_REPO" config user.email "oss-vuln-digger@example.invalid"
git -C "$IMPACT_REPO" config user.name "oss-vuln-digger fixture"

import_release "5.29.4"
import_release "5.29.5"

python3 -c '
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
repository = sys.argv[3]
payload = json.loads(source.read_text(encoding="utf-8"))
payload["version_source"]["repository"] = repository
target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
' "$MANIFEST" "$RUNTIME_MANIFEST" "$IMPACT_REPO"

python3 -m oss_vuln_digger \
  --config "$ROOT_DIR/config.host.example.toml" \
  --runs-dir "$RUNS_DIR" \
  impact assess "$RUNTIME_MANIFEST"
