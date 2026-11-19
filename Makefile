.PHONY: build build-agent build-headless build-all build-release-matrix test test-integration test-e2e test-sandbox test-sandbox-live lint clean dev dev-sandbox build-sandbox-upstream help

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

## Build
build: web-build ## Build orchestrator binary (rebuilds dashboard assets first)
	go build $(LDFLAGS) -o nurproxy ./cmd/nurproxy

build-agent: ## Build agent binary
	go build $(LDFLAGS) -o nurproxy-agent ./cmd/nurproxy-agent

build-headless: ## Build headless orchestrator (no embedded dashboard, API+CLI only)
	go build -tags headless $(LDFLAGS) -o nurproxy-headless ./cmd/nurproxy

build-all: build build-agent ## Build both binaries

RELEASE_TARGETS := linux/amd64 linux/arm64 linux/arm/v7 darwin/amd64 darwin/arm64 freebsd/amd64 freebsd/arm64

build-release-matrix: ## Cross-build both binaries for every GoReleaser target
	@set -eu; \
	out=$$(mktemp -d); \
	trap 'rm -rf "$$out"' EXIT HUP INT TERM; \
	for target in $(RELEASE_TARGETS); do \
		goos=$${target%%/*}; \
		rest=$${target#*/}; \
		goarch=$${rest%%/*}; \
		goarm=; \
		if [ "$$goarch" = arm ]; then goarm=$${rest#*/v}; fi; \
		name=$$(printf '%s' "$$target" | tr / -); \
		for binary in nurproxy nurproxy-agent; do \
			CGO_ENABLED=0 GOOS="$$goos" GOARCH="$$goarch" GOARM="$$goarm" \
				go build -trimpath -o "$$out/$${binary}_$${name}" "./cmd/$$binary"; \
		done; \
	done

## Test
test: ## Run unit tests
	go test -race -count=1 -timeout=20m ./...

test-integration: ## Run integration tests
	go test -race -count=1 -tags=integration ./...

test-e2e: ## Run E2E tests
	go test -race -count=1 -tags=e2e ./...

test-sandbox: build-headless build-agent ## Run the sandbox e2e tests (full stack, no external deps; real-proxy checks when caddy/nginx exist)
	go test -count=1 -tags=sandbox -timeout=480s ./test/sandbox/...

test-sandbox-live: ## Run the live sandbox e2e test (real Caddy on loopback ports; skips without caddy)
	go test -count=1 -tags=sandbox -timeout=180s -run TestSandboxLiveTraffic -v ./test/sandbox/...

test-cover: ## Run tests with coverage
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

## Lint
lint: ## Run linters
	golangci-lint run ./...

lint-fix: ## Run linters with auto-fix
	golangci-lint run --fix ./...

## Sandbox
dev-sandbox: build build-agent build-sandbox-upstream ## Bring up a full sandbox stack and seed it (PROFILE=live for a real Caddy)
	ORCH_BIN=./nurproxy AGENT_BIN=./nurproxy-agent UPSTREAM_BIN=./nurproxy-sandbox-upstream ./scripts/dev-sandbox.sh

build-sandbox-upstream: ## Build the fake upstream the live sandbox proxies to
	go build -tags sandbox -o nurproxy-sandbox-upstream ./test/sandbox/fakeupstream

## Frontend
dev: ## Run dashboard dev server
	cd web && npm run dev

web-build: ## Build dashboard assets
	cd web && npm ci && npm run build

web-install: ## Install dashboard dependencies
	cd web && npm install

## Clean
clean: ## Remove build artifacts
	rm -f nurproxy nurproxy-agent nurproxy-sandbox-upstream
	rm -f coverage.out coverage.html
	rm -rf web/dist

## Help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
