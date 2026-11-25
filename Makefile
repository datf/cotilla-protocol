# cotilla — build targets
#
# Requires Go 1.27+ (with GA goroutineleak profiles; see go.mod).
# `GOTOOLCHAIN=auto` will fetch the pinned toolchain automatically.
# Dependencies are vendored (vendor/, ADR-0009); Go builds against it automatically.

GO ?= go
WEB := web
WASM_FLAGS := -ldflags="-s -w" -trimpath

.PHONY: all init submodules wasm clib server seeder bootstrap bootstrap-singlefile bootstrap-svelte svelte-bundle test tests perf vendor vuln run tidy clean testbench testbench-up testbench-down testbench-test

all: vendor wasm clib server seeder bootstrap svelte-bundle

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

## wasm: build the browser protocol library (js/wasm) into web/ (ADR-0005)
wasm:
	GOOS=js GOARCH=wasm $(GO) build $(WASM_FLAGS) -o $(WEB)/cotilla.wasm ./wasm
	@install -m 0644 "$$($(GO) env GOROOT)/lib/wasm/wasm_exec.js" $(WEB)/wasm_exec.js

## clib: build the protocol core as a C dynamic library for foreign native apps (ADR-0005)
clib:
	@mkdir -p bin
	CGO_ENABLED=1 $(GO) build -tags clib -buildmode=c-shared -o bin/libcotilla.so ./clib

## server: build the bootstrap/signaling/relay server (coder/websocket, ADR-0008)
server:
	@mkdir -p bin
	$(GO) build -o bin/cotilla-server ./cmd/server

## seeder: build the headless P2P app bundle distribution seeder CLI
seeder:
	@mkdir -p bin
	$(GO) build -o bin/cotilla-seeder ./cmd/seeder

## bootstrap: build strictly 2-file bootstrap directory (index.html + cotilla.wasm) and signed chat bundle
bootstrap: wasm seeder
	@mkdir -p bootstrap dist
	GOOS=js GOARCH=wasm $(GO) build $(WASM_FLAGS) -o bootstrap/cotilla.wasm ./wasm
	$(GO) run ./cmd/bootstrapgen
	@echo "Checking bootstrap/ contents (strictly 2 files):"
	@test "$$(ls -1 bootstrap | sort | tr '\n' ' ')" = "cotilla.wasm index.html " || (echo "ERROR: bootstrap/ must contain only cotilla.wasm and index.html" && exit 1)

## bootstrap-singlefile: build single-file self-contained bootstrap HTML into cotilla-bootstrap/dist/index.html
bootstrap-singlefile: bootstrap cotilla-bootstrap/node_modules/.package-lock.json
	@cp bootstrap/cotilla.wasm cotilla-bootstrap/cotilla.wasm
	npm --prefix cotilla-bootstrap run build
	@echo "Checking cotilla-bootstrap/dist/ contents (strictly 1 file):"
	@test "$$(ls -1 cotilla-bootstrap/dist | sort | tr '\n' ' ')" = "index.html " || (echo "ERROR: cotilla-bootstrap/dist/ must contain only index.html" && exit 1)

## svelte-bundle: build minimized single-file Svelte app and sign as cotilla-svelte
svelte-bundle: bootstrap seeder svelte/node_modules/.modules.yaml cotilla-bootstrap/node_modules/.package-lock.json
	@mkdir -p dist
	pnpm --prefix svelte run build:singlefile
	@cp svelte/dist-singlefile/singlefile.html dist/cotilla-svelte.html
	./bin/cotilla-seeder -sign -bundle dist/cotilla-svelte.html -app-id cotilla-svelte -key-file dist/publisher.json -out dist/cotilla-svelte.manifest.json
	@echo "Checking dist/cotilla-svelte.html bundle:"
	@test -f dist/cotilla-svelte.html && test -f dist/cotilla-svelte.manifest.json || (echo "ERROR: missing svelte bundle or manifest" && exit 1)

## bootstrap-svelte: build single-file cotilla-bootstrap configured for cotilla-svelte
bootstrap-svelte: svelte-bundle cotilla-bootstrap/node_modules/.package-lock.json
	@cp bootstrap/cotilla.wasm cotilla-bootstrap/cotilla.wasm
	COTILLA_MANIFEST=../dist/cotilla-svelte.manifest.json npm --prefix cotilla-bootstrap run build
	@echo "Checking cotilla-bootstrap/dist/ contents for cotilla-svelte:"
	@test "$$(ls -1 cotilla-bootstrap/dist | sort | tr '\n' ' ')" = "index.html " || (echo "ERROR: cotilla-bootstrap/dist/ must contain only index.html" && exit 1)

## test: run all Go tests (library + pion transport). Use `-short` to skip heavy perf/scaling tests.
test: bootstrap
	$(GO) test ./...

tests: test

## perf: run full performance, capacity, hop-limit, island-prevention, and Go 1.27 goroutineleak suites
perf:
	$(GO) test -v -timeout 10m -run "TestPerf_|Benchmark" ./pkg/cotilla ./cmd/server ./cmd/seeder ./cmd/node

## run: build the web assets + server and start it on :8080
run: all
	./bin/cotilla-server -addr 0.0.0.0:8080 -web $(WEB)

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
	rm -rf bin $(WEB)/cotilla.wasm $(WEB)/wasm_exec.js bootstrap dist cotilla-bootstrap/dist cotilla-bootstrap/src/vendor cotilla-bootstrap/cotilla.wasm svelte/dist-singlefile
	-$(MAKE) -C testbench clean

