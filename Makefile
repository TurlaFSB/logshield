SHELL := /bin/bash
.DEFAULT_GOAL := help

VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
PKG     := github.com/TurlaFSB/logshield
LDFLAGS := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.Date=$(DATE)

# Minimum total statement coverage, in percent. Raised as the engine matures
# (target 90 by the end of Step 1).
COVER_MIN ?= 80
GOVULNCHECK_VERSION := v1.1.4

.PHONY: help build test race cover cover-check fmt vet lint vuln check

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

build: ## Build the logshield binary into ./bin
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/logshield ./cmd/logshield

test: ## Run unit tests
	go test ./...

race: ## Run unit tests with the race detector
	go test -race ./...

cover: ## Run tests and write coverage.out
	go test -race -covermode=atomic -coverprofile=coverage.out ./...

cover-check: cover ## Fail if total coverage is below COVER_MIN
	@total=$$(go tool cover -func=coverage.out | awk '/^total:/ {gsub("%","",$$3); print $$3}'); \
	echo "total coverage: $$total% (floor: $(COVER_MIN)%)"; \
	awk -v t="$$total" -v m="$(COVER_MIN)" 'BEGIN { exit (t+0 >= m+0) ? 0 : 1 }' || \
	  { echo "coverage $$total% is below the $(COVER_MIN)% floor"; exit 1; }

fmt: ## Format code
	gofmt -s -w .

vet: ## Run go vet
	go vet ./...

lint: ## Run golangci-lint
	golangci-lint run ./...

vuln: ## Scan dependencies and stdlib for known vulnerabilities
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

check: vet lint cover-check ## Everything CI runs, minus govulncheck
