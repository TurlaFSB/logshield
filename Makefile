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

# Minimum total statement coverage, in percent. This is a ratchet: it only goes up.
COVER_MIN ?= 90
GOVULNCHECK_VERSION := v1.1.4
FUZZTIME ?= 30s
FUZZ_TARGETS := FuzzDecode FuzzResolve FuzzInspect

.PHONY: help build test race cover cover-check fuzz bench eval fmt vet lint vuln check

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

fuzz: ## Fuzz each target for FUZZTIME (default 30s)
	@for t in $(FUZZ_TARGETS); do \
	  echo "fuzzing $$t for $(FUZZTIME)"; \
	  go test ./internal/engine -run '^$$' -fuzz="^$$t$$" -fuzztime=$(FUZZTIME) || exit 1; \
	done

bench: ## Run benchmarks
	go test ./internal/engine -run '^$$' -bench . -benchmem

eval: ## Regenerate docs/eval/report.md from the corpora (fails if a target is missed)
	go test ./internal/corpus -run TestEvaluationTargets -count=1 -update

fmt: ## Format code
	gofmt -s -w .

vet: ## Run go vet
	go vet ./...

lint: ## Run golangci-lint
	golangci-lint run ./...

vuln: ## Scan dependencies and stdlib for known vulnerabilities
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

check: vet lint cover-check ## Everything CI runs, minus govulncheck
