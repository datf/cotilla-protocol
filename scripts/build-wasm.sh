#!/usr/bin/env bash
set -euo pipefail

# Build the Cotilla WebAssembly core once into dist/wasm/ (minimal self-contained WASM package).
# Outputs:
#   dist/wasm/cotilla.wasm
#   dist/wasm/wasm_exec.js   (copied from the exact Go GOROOT that compiled cotilla.wasm)
#   dist/wasm/package.json

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/dist/wasm}"

VERSION="${VERSION:-$(git -C "${ROOT_DIR}" describe --tags --always --dirty 2>/dev/null || echo dev)}"
COMMIT="${COMMIT:-$(git -C "${ROOT_DIR}" rev-parse --short HEAD 2>/dev/null || echo none)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

BUILDINFO_PKG="github.com/datf/cotilla-protocol/internal/buildinfo"
LDFLAGS="-s -w -X ${BUILDINFO_PKG}.Version=${VERSION} -X ${BUILDINFO_PKG}.Commit=${COMMIT} -X ${BUILDINFO_PKG}.Date=${BUILD_DATE}"

# Normalize Go/git version string into a valid npm semver string.
npm_version() {
	local v="${1#v}"
	if [[ "${v}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]; then
		printf '%s' "${v}"
	else
		local safe
		safe="$(printf '%s' "${v}" | tr -cs '0-9A-Za-z.-' '-' | sed 's/^-//;s/-$//')"
		printf '0.0.0-dev.%s' "${safe:-local}"
	fi
}

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

# 1. Compile ./wasm once
(
	cd "${ROOT_DIR}"
	CGO_ENABLED=0 GOOS=js GOARCH=wasm go build -trimpath -ldflags="${LDFLAGS}" -o "${OUT_DIR}/cotilla.wasm" ./wasm
)

# 2. Copy compiler-matched wasm_exec.js directly from active Go GOROOT
GOROOT_DIR="$(go env GOROOT)"
if [[ -f "${GOROOT_DIR}/lib/wasm/wasm_exec.js" ]]; then
	install -m 0644 "${GOROOT_DIR}/lib/wasm/wasm_exec.js" "${OUT_DIR}/wasm_exec.js"
elif [[ -f "${GOROOT_DIR}/misc/wasm/wasm_exec.js" ]]; then
	install -m 0644 "${GOROOT_DIR}/misc/wasm/wasm_exec.js" "${OUT_DIR}/wasm_exec.js"
else
	echo "ERROR: wasm_exec.js not found in GOROOT (${GOROOT_DIR})" >&2
	exit 1
fi

# 3. Stamp package.json version into dist/wasm/package.json
NPM_VER="$(npm_version "${VERSION}")"
sed "s/\"version\": \"[^\"]*\"/\"version\": \"${NPM_VER}\"/" "${ROOT_DIR}/wasm/package.json" > "${OUT_DIR}/package.json"

echo "Built dist/wasm (${VERSION}, npm=${NPM_VER}):"
ls -lh "${OUT_DIR}/cotilla.wasm" "${OUT_DIR}/wasm_exec.js"
