PODMAN ?= podman
COMPOSE ?= podman compose

.PHONY: all bin build up down test test-svelte test-browser clean logs

all: build
	$(COMPOSE) down -v
	$(COMPOSE) up -d
	@status=0; \
		./bin/runner && $(MAKE) test-browser || status=$$?; \
		$(COMPOSE) down -v; \
		exit $$status

bin:
	mkdir -p bin
	$(MAKE) -C .. bootstrap-svelte
	rm -rf web && cp -r ../web ./web
	mkdir -p web/svelte && cp ../cotilla-bootstrap/dist/index.html ./web/svelte/index.html
	rm -rf dist && mkdir -p dist && cp ../dist/cotilla-svelte.html ../dist/cotilla-svelte.manifest.json ../dist/publisher.json ./dist/
	CGO_ENABLED=0 go build -o bin/cotilla-server ../cmd/server
	CGO_ENABLED=0 go build -o bin/cotilla-test-client ./client
	CGO_ENABLED=0 go build -o bin/cotilla-seeder ../cmd/seeder
	go build -o bin/runner ./runner

build: bin
	$(PODMAN) build -t cotilla-server:testbench -f Containerfile.server .
	$(PODMAN) build -t cotilla-client:testbench -f Containerfile.client .
	$(PODMAN) build -t cotilla-seeder:testbench -f Containerfile.seeder .
	$(PODMAN) build -t cotilla-browser:testbench -f Containerfile.browser .

up: build
	$(COMPOSE) up -d

down:
	$(COMPOSE) down -v

test: bin
	./bin/runner

test-svelte:
	$(PODMAN) run --rm --network testbench_cotilla-bench -e SERVER_URL=http://cotilla-signaling:8080 -e SVELTE_URL=http://cotilla-signaling:8080/svelte/ -e SEEDER_URL=http://cotilla-seeder:8081 -e NATIVE_ALICE_URL=http://cotilla-alice:8080 -e NATIVE_BOB_URL=http://cotilla-bob:8080 -e NATIVE_CHARLIE_URL=http://cotilla-charlie:8080 cotilla-browser:testbench test_svelte.js

test-browser: test-svelte
	$(PODMAN) run --rm --network testbench_cotilla-bench -e SERVER_URL=http://cotilla-signaling:8080 -e NATIVE_ALICE_URL=http://cotilla-alice:8080 -e NATIVE_BOB_URL=http://cotilla-bob:8080 -e NATIVE_CHARLIE_URL=http://cotilla-charlie:8080 cotilla-browser:testbench test.js

logs:
	$(COMPOSE) logs

clean: down
	rm -rf bin web dist
