#!/usr/bin/env bash
set -euo pipefail

# Build the MIT-licensed StarUDP/Hysteria-v1 client for Windows x64.
# This is a build-only helper: it does not install, launch, or connect the client.

readonly STARUDP_REPOSITORY="https://github.com/starrising321/starudp.git"
readonly STARUDP_COMMIT="23fa29bb4fad600330b30e2b703b8029ef091446"
readonly WORK_ROOT="${TMPDIR:-/tmp}/apnawin-starudp-${STARUDP_COMMIT}"
readonly SOURCE_ROOT="${WORK_ROOT}/source"
readonly OUTPUT_DIR="${APNAWIN_UDPQ_OUTPUT_DIR:-${TMPDIR:-/tmp}/apnawin-udpq-build}"

command -v git >/dev/null 2>&1 || {
  echo "git is required to fetch the pinned StarUDP source." >&2
  exit 2
}
command -v go >/dev/null 2>&1 || {
  echo "Go is required to build the Windows x64 sidecar." >&2
  exit 2
}

if [[ ! -d "${SOURCE_ROOT}/.git" ]]; then
  mkdir -p "${WORK_ROOT}"
  git clone --no-checkout "${STARUDP_REPOSITORY}" "${SOURCE_ROOT}"
fi

git -C "${SOURCE_ROOT}" fetch --depth 1 origin "${STARUDP_COMMIT}"
git -C "${SOURCE_ROOT}" checkout --detach "${STARUDP_COMMIT}"

actual_commit="$(git -C "${SOURCE_ROOT}" rev-parse HEAD)"
if [[ "${actual_commit}" != "${STARUDP_COMMIT}" ]]; then
  echo "Pinned StarUDP commit mismatch: ${actual_commit}" >&2
  exit 3
fi

mkdir -p "${OUTPUT_DIR}"
(
  cd "${SOURCE_ROOT}/app"
  GOTOOLCHAIN=local GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
    go build -trimpath -ldflags="-s -w" \
      -o "${OUTPUT_DIR}/udpq-client.exe" ./cmd
)

go version -m "${OUTPUT_DIR}/udpq-client.exe"
if command -v file >/dev/null 2>&1; then
  file "${OUTPUT_DIR}/udpq-client.exe"
fi

echo "Built Windows x64 sidecar: ${OUTPUT_DIR}/udpq-client.exe"
echo "Pinned source commit: ${STARUDP_COMMIT}"
echo "The executable has not been launched and no remote server was contacted."
