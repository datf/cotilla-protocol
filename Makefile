# cotilla — build & release targets
#
# Requires Go 1.27+ (with GA goroutineleak profiles; see go.mod).
# `GOTOOLCHAIN=auto` will fetch the pinned toolchain automatically.
# Dependencies are vendored (vendor/, ADR-0009); Go builds against it automatically.
# All generated build and release artifacts live under dist/.

GO ?= go
DIST := dist
WEB_SRC := web
WEB_DIST := $(DIST)/web
BIN_DIST := $(DIST)/bin
WASM_DIST := $(DIST)/wasm
CLIB_DIST := $(DIST)/clib
BOOTSTRAP_DIST := $(DIST)/bootstrap
APPS_DIST := $(DIST)/apps
DEV_DIST := $(DIST)/dev
RELEASE_DIST := $(DIST)/release

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

BUILDINFO_PKG := github.com/datf/cotilla-protocol/internal/buildinfo
LDFLAGS := -s -w -X $(BUILDINFO_PKG).Version=$(VERSION) -X $(BUILDINFO_PKG).Commit=$(COMMIT) -X $(BUILDINFO_PKG).Date=$(BUILD_DATE)

HOST_GOOS := $(shell $(GO) env GOOS)
HOST_GOARCH := $(shell $(GO) env GOARCH)
TARGET_GOOS ?= $(HOST_GOOS)
TARGET_GOARCH ?= $(HOST_GOARCH)

ifeq ($(HOST_GOOS),darwin)
CLIB_EXT := dylib
else ifeq ($(HOST_GOOS),windows)
CLIB_EXT := dll
else
CLIB_EXT := so
endif

.PHONY: all init submodules wasm web clib server seeder node bins \
	bootstrap bootstrap-singlefile bootstrap-svelte svelte-bundle svelte-build \
	release-bin release-wasm release-clib \
	test tests perf vendor vuln run tidy clean \
	testbench testbench-up testbench-down testbench-test

all: vendor wasm web clib bins bootstrap svelte-bundle

## submodules: initialize git submodules (svelte, cotilla-bootstrap)
submodules:
	git submodule update --init --recursive

## init: initialize git submodules and install JS dependencies for svelte and cotilla-bootstrap
init: submodules svelte/node_modules/.modules.yaml cotilla-bootstrap/node_modules/.package-lock.json

svelte/pnpm-lock.yaml:
	git submodule update --init --recursive svelte

cotilla-bootstrap/package-lock.json:
	git submodule update --init --recursive cotilla-bootstrap

svelte/node_modules/.modules.yaml: svelte/pnpm-lock.yaml
	pnpm --prefix svelte install --frozen-lockfile
	@touch $@

cotilla-bootstrap/node_modules/.package-lock.json: cotilla-bootstrap/package-lock.json
	npm --prefix cotilla-bootstrap ci
	@touch $@

## wasm: compile ./wasm once into dist/wasm/ (cotilla.wasm, wasm_exec.js, package.json)
wasm:
	VERSION="$(VERSION)" COMMIT="$(COMMIT)" BUILD_DATE="$(BUILD_DATE)" ./scripts/build-wasm.sh

## web: stage static web assets into dist/web/ (keeps web/ pure source)
web: wasm
	@mkdir -p $(WEB_DIST)
	@cp -R $(WEB_SRC)/. $(WEB_DIST)/
	@install -m 0644 $(WASM_DIST)/cotilla.wasm $(WEB_DIST)/cotilla.wasm
	@install -m 0644 $(WASM_DIST)/wasm_exec.js $(WEB_DIST)/wasm_exec.js

## clib: build the protocol core as a C dynamic library into dist/clib/ (ADR-0005)
clib:
	@mkdir -p $(CLIB_DIST)
	CGO_ENABLED=1 $(GO) build -tags clib -buildmode=c-shared -trimpath -ldflags="$(LDFLAGS)" -o $(CLIB_DIST)/libcotilla.$(CLIB_EXT) ./clib

## server: build the bootstrap/signaling/relay server into dist/bin/ (ADR-0008)
server:
	@mkdir -p $(BIN_DIST)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIST)/cotilla-server ./cmd/server

## seeder: build the headless P2P app bundle distribution seeder CLI into dist/bin/
seeder:
	@mkdir -p $(BIN_DIST)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIST)/cotilla-seeder ./cmd/seeder

## node: build the headless P2P node daemon into dist/bin/
node:
	@mkdir -p $(BIN_DIST)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIST)/cotilla-node ./cmd/node

## bins: build all host Go binaries into dist/bin/
bins: server seeder node

## bootstrap: build strictly 2-file dist/bootstrap/ (index.html + cotilla.wasm) and signed chat bundle in dist/apps/
bootstrap: wasm seeder
	@mkdir -p $(BOOTSTRAP_DIST) $(APPS_DIST) $(DEV_DIST)
	@install -m 0644 $(WASM_DIST)/cotilla.wasm $(BOOTSTRAP_DIST)/cotilla.wasm
	$(GO) run ./cmd/bootstrapgen
	@echo "Checking $(BOOTSTRAP_DIST)/ contents (strictly 2 files):"
	@test "$$(ls -1 $(BOOTSTRAP_DIST) | sort | tr '\n' ' ')" = "cotilla.wasm index.html " || (echo "ERROR: $(BOOTSTRAP_DIST)/ must contain only cotilla.wasm and index.html" && exit 1)

## bootstrap-singlefile: build single-file self-contained bootstrap HTML into cotilla-bootstrap/dist/index.html and dist/apps/
bootstrap-singlefile: bootstrap cotilla-bootstrap/node_modules/.package-lock.json
	@mkdir -p $(APPS_DIST)
	COTILLA_WASM_DIR="$(CURDIR)/$(WASM_DIST)" npm --prefix cotilla-bootstrap run build
	@cp cotilla-bootstrap/dist/index.html $(APPS_DIST)/cotilla-chat-bootstrap.html
	@echo "Checking cotilla-bootstrap/dist/ contents (strictly 1 file):"
	@test "$$(ls -1 cotilla-bootstrap/dist | sort | tr '\n' ' ')" = "index.html " || (echo "ERROR: cotilla-bootstrap/dist/ must contain only index.html" && exit 1)

## svelte-bundle: build minimized single-file Svelte app and sign as cotilla-svelte into dist/apps/
svelte-bundle: bootstrap seeder svelte/node_modules/.modules.yaml
	@mkdir -p $(APPS_DIST)
	COTILLA_WASM_DIR="$(CURDIR)/$(WASM_DIST)" pnpm --prefix svelte run build:singlefile
	@cp svelte/dist-singlefile/singlefile.html $(APPS_DIST)/cotilla-svelte.html
	./$(BIN_DIST)/cotilla-seeder -sign -bundle $(APPS_DIST)/cotilla-svelte.html -app-id cotilla-svelte -key-file $(DEV_DIST)/publisher.json -out $(APPS_DIST)/cotilla-svelte.manifest.json
	@echo "Checking $(APPS_DIST)/cotilla-svelte.html bundle:"
	@test -f $(APPS_DIST)/cotilla-svelte.html && test -f $(APPS_DIST)/cotilla-svelte.manifest.json || (echo "ERROR: missing svelte bundle or manifest" && exit 1)

## bootstrap-svelte: build single-file cotilla-bootstrap configured for cotilla-svelte
bootstrap-svelte: svelte-bundle cotilla-bootstrap/node_modules/.package-lock.json
	@mkdir -p $(APPS_DIST)
	COTILLA_MANIFEST="$(CURDIR)/$(APPS_DIST)/cotilla-svelte.manifest.json" COTILLA_WASM_DIR="$(CURDIR)/$(WASM_DIST)" npm --prefix cotilla-bootstrap run build
	@cp cotilla-bootstrap/dist/index.html $(APPS_DIST)/cotilla-svelte-bootstrap.html
	@echo "Checking cotilla-bootstrap/dist/ contents for cotilla-svelte:"
	@test "$$(ls -1 cotilla-bootstrap/dist | sort | tr '\n' ' ')" = "index.html " || (echo "ERROR: cotilla-bootstrap/dist/ must contain only index.html" && exit 1)

## svelte-build: build standard Svelte SPA using local dist/wasm/
svelte-build: wasm svelte/node_modules/.modules.yaml
	COTILLA_WASM_DIR="$(CURDIR)/$(WASM_DIST)" pnpm --prefix svelte run build

## release-bin: cross-compile server, seeder, and node for TARGET_GOOS/TARGET_GOARCH into dist/release/
release-bin:
	@set -eu; \
	os="$(TARGET_GOOS)"; arch="$(TARGET_GOARCH)"; \
	ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
	base="cotilla-$(VERSION)-$$os-$$arch"; \
	stage="$(RELEASE_DIST)/stage-$$os-$$arch/$$base"; \
	rm -rf "$(RELEASE_DIST)/stage-$$os-$$arch"; \
	mkdir -p "$$stage"; \
	CGO_ENABLED=0 GOOS="$$os" GOARCH="$$arch" $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o "$$stage/cotilla-server$$ext" ./cmd/server; \
	CGO_ENABLED=0 GOOS="$$os" GOARCH="$$arch" $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o "$$stage/cotilla-seeder$$ext" ./cmd/seeder; \
	CGO_ENABLED=0 GOOS="$$os" GOARCH="$$arch" $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o "$$stage/cotilla-node$$ext" ./cmd/node; \
	[ -f README.md ] && cp README.md "$$stage/"; \
	[ -f LICENSE ] && cp LICENSE "$$stage/"; \
	if [ "$$os" = "windows" ]; then \
		(cd "$(RELEASE_DIST)/stage-$$os-$$arch" && zip -q -r "$(CURDIR)/$(RELEASE_DIST)/$$base.zip" "$$base"); \
	else \
		tar -C "$(RELEASE_DIST)/stage-$$os-$$arch" -czf "$(RELEASE_DIST)/$$base.tar.gz" "$$base"; \
	fi; \
	rm -rf "$(RELEASE_DIST)/stage-$$os-$$arch"

## release-wasm: package dist/wasm/ into dist/release/ (tar.gz, zip, npm .tgz, raw cotilla.wasm)
release-wasm: wasm
	@set -eu; \
	mkdir -p "$(RELEASE_DIST)"; \
	base="cotilla-wasm-$(VERSION)"; \
	stage="$(RELEASE_DIST)/stage-wasm/$$base"; \
	rm -rf "$(RELEASE_DIST)/stage-wasm"; \
	mkdir -p "$$stage"; \
	cp "$(WASM_DIST)/cotilla.wasm" "$(WASM_DIST)/wasm_exec.js" "$(WASM_DIST)/package.json" "$$stage/"; \
	tar -C "$(RELEASE_DIST)/stage-wasm" -czf "$(RELEASE_DIST)/$$base.tar.gz" "$$base"; \
	if command -v zip >/dev/null 2>&1; then \
		(cd "$(RELEASE_DIST)/stage-wasm" && zip -q -r "$(CURDIR)/$(RELEASE_DIST)/$$base.zip" "$$base"); \
	fi; \
	rm -rf "$(RELEASE_DIST)/stage-wasm"; \
	cp "$(WASM_DIST)/cotilla.wasm" "$(RELEASE_DIST)/cotilla.wasm"; \
	if command -v npm >/dev/null 2>&1; then \
		(cd "$(WASM_DIST)" && npm_config_cache="$${TMPDIR:-/tmp}/cotilla-npm-cache" npm pack --silent --pack-destination "$(CURDIR)/$(RELEASE_DIST)"); \
	fi

## release-clib: package host C shared library (dist/clib/) into dist/release/
release-clib: clib
	@set -eu; \
	mkdir -p "$(RELEASE_DIST)"; \
	base="cotilla-clib-$(VERSION)-$(HOST_GOOS)-$(HOST_GOARCH)"; \
	stage="$(RELEASE_DIST)/stage-clib/$$base"; \
	rm -rf "$(RELEASE_DIST)/stage-clib"; \
	mkdir -p "$$stage"; \
	cp "$(CLIB_DIST)/libcotilla.$(CLIB_EXT)" "$(CLIB_DIST)/libcotilla.h" "$$stage/"; \
	if [ "$(HOST_GOOS)" = "windows" ]; then \
		(cd "$(RELEASE_DIST)/stage-clib" && zip -q -r "$(CURDIR)/$(RELEASE_DIST)/$$base.zip" "$$base"); \
	else \
		tar -C "$(RELEASE_DIST)/stage-clib" -czf "$(RELEASE_DIST)/$$base.tar.gz" "$$base"; \
	fi; \
	rm -rf "$(RELEASE_DIST)/stage-clib"

## test: run all Go tests (library + pion transport). Use `-short` to skip heavy perf/scaling tests.
test: bootstrap
	$(GO) test ./...

tests: test perf testbench

## perf: run full performance, capacity, hop-limit, island-prevention, and Go 1.27 goroutineleak suites
perf:
	$(GO) test -v -timeout 10m -run "TestPerf_|Benchmark" ./pkg/cotilla ./cmd/server ./cmd/seeder ./cmd/node

## run: build the web assets + server and start it on :8080
run: server web
	./$(BIN_DIST)/cotilla-server -addr 0.0.0.0:8080 -web $(WEB_DIST)

## vendor: refresh the vendored dependency tree after a dependency change (ADR-0009)
vendor:
	$(GO) mod tidy
	$(GO) mod vendor

## vuln: reachability-based vulnerability scan (needs golang.org/x/vuln/cmd/govulncheck)
vuln:
	govulncheck ./...

tidy:
	$(GO) mod tidy

## testbench: run full end-to-end multi-client tests in containerized test bench (podman)
testbench:
	$(MAKE) -C testbench all

testbench-up:
	$(MAKE) -C testbench up

testbench-down:
	$(MAKE) -C testbench down

testbench-test:
	$(MAKE) -C testbench test

clean:
	rm -rf $(DIST) bin bootstrap $(WEB_SRC)/cotilla.wasm $(WEB_SRC)/wasm_exec.js cotilla-bootstrap/dist cotilla-bootstrap/src/vendor cotilla-bootstrap/cotilla.wasm svelte/dist-singlefile svelte/static svelte/build
	-$(MAKE) -C testbench clean
