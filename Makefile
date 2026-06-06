.PHONY: build build-agent build-headless build-all test test-integration test-e2e test-sandbox lint clean dev dev-sandbox help

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

## Test
test: ## Run unit tests
	go test -race -count=1 ./...

test-integration: ## Run integration tests
	go test -race -count=1 -tags=integration ./...

test-e2e: ## Run E2E tests
	go test -race -count=1 -tags=e2e ./...

test-sandbox: build-headless build-agent ## Run the dry-run sandbox e2e test (full stack, no external deps)
	go test -count=1 -tags=sandbox -timeout=120s ./test/sandbox/...

test-cover: ## Run tests with coverage
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

## Lint
lint: ## Run linters
	golangci-lint run ./...

lint-fix: ## Run linters with auto-fix
	golangci-lint run --fix ./...

## Sandbox
dev-sandbox: build build-agent ## Bring up a full dry-run stack (orchestrator + agents) and seed it
	ORCH_BIN=./nurproxy AGENT_BIN=./nurproxy-agent ./scripts/dev-sandbox.sh

## Frontend
dev: ## Run dashboard dev server
	cd web && npm run dev

web-build: ## Build dashboard assets
	cd web && npm ci && npm run build

web-install: ## Install dashboard dependencies
	cd web && npm install

## Clean
clean: ## Remove build artifacts
	rm -f nurproxy nurproxy-agent
	rm -f coverage.out coverage.html
	rm -rf web/dist

## Help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
