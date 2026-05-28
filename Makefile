.PHONY: build build-agent build-all test test-integration test-e2e lint clean dev help

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

## Build
build: web-build ## Build orchestrator binary (rebuilds dashboard assets first)
	go build $(LDFLAGS) -o nurproxy ./cmd/nurproxy

build-agent: ## Build agent binary
	go build $(LDFLAGS) -o nurproxy-agent ./cmd/nurproxy-agent

build-all: build build-agent ## Build both binaries

## Test
test: ## Run unit tests
	go test -race -count=1 ./...

test-integration: ## Run integration tests
	go test -race -count=1 -tags=integration ./...

test-e2e: ## Run E2E tests
	go test -race -count=1 -tags=e2e ./...

test-cover: ## Run tests with coverage
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

## Lint
lint: ## Run linters
	golangci-lint run ./...

lint-fix: ## Run linters with auto-fix
	golangci-lint run --fix ./...

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
