#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_ROOT="${1:-$ROOT_DIR/.targets}"
RUNS_DIR="${OVL_RUNS_DIR:-$ROOT_DIR/.ovl_runs}"
mkdir -p "$TARGET_ROOT"
IMPACT_REPO="$(mktemp -d "$TARGET_ROOT/zlib-cve-2022-37434-git.XXXXXX")"
MANIFEST="$ROOT_DIR/examples/impact/zlib-cve-2022-37434.json"
RUNTIME_MANIFEST="$TARGET_ROOT/zlib-cve-2022-37434-impact.json"

fetch_release() {
  local version="$1"
  local sha256="$2"
  local archive="$TARGET_ROOT/zlib-$version.tar.gz"
  local extracted="$TARGET_ROOT/zlib-$version"
  local url="https://www.zlib.net/fossils/zlib-$version.tar.gz"

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
  local extracted="$TARGET_ROOT/zlib-$version"

  rsync -a --delete --exclude .git "$extracted"/ "$IMPACT_REPO"/
  git -C "$IMPACT_REPO" add -A
  git -C "$IMPACT_REPO" commit -m "Import zlib $version"
  git -C "$IMPACT_REPO" tag "v$version"
}

fetch_release "1.2.12" "91844808532e5ce316b3c010929493c0244f3d37593afd6de04f71821d5136d9"
fetch_release "1.2.13" "b3a24de97a8fdbc835b9833169501030b8977031bcb54b3b3ac13740f846ab30"

git -C "$IMPACT_REPO" init
git -C "$IMPACT_REPO" config user.email "oss-vuln-lab@example.invalid"
git -C "$IMPACT_REPO" config user.name "oss-vuln-lab fixture"

import_release "1.2.12"
import_release "1.2.13"

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

python3 -m oss_vuln_lab \
  --config "$ROOT_DIR/config.host.example.toml" \
  --runs-dir "$RUNS_DIR" \
  impact assess "$RUNTIME_MANIFEST"
