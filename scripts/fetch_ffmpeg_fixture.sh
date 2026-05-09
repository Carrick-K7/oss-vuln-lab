#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${ROOT_DIR}/.targets"
ARCHIVE="${TARGET_DIR}/ffmpeg-7.1.1.tar.xz"
SOURCE_DIR="${TARGET_DIR}/ffmpeg-7.1.1"

mkdir -p "${TARGET_DIR}"

if [[ ! -f "${ARCHIVE}" ]]; then
  curl -L "https://ffmpeg.org/releases/ffmpeg-7.1.1.tar.xz" -o "${ARCHIVE}"
fi

if [[ ! -d "${SOURCE_DIR}" ]]; then
  tar -C "${TARGET_DIR}" -xf "${ARCHIVE}"
fi

printf 'Ready: %s\n' "${SOURCE_DIR}"
