# thinkpol-vpn development targets. `make help` lists them.

GOBIN := $(shell go env GOPATH)/bin
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# No cgo anywhere: the data plane has to stay buildable for mobile.
export CGO_ENABLED := 0

.PHONY: help build test lint fmt tools lab-up lab-test lab-down

help: ## list targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-14s %s\n", $$1, $$2}'

build: ## build bin/thinkpol for this machine
	go build -trimpath -ldflags "-X main.version=$(VERSION)" -o bin/thinkpol ./cmd/thinkpol

test: ## unit tests
	go test ./...

lint: ## gofmt check + go vet + golangci-lint
	@fmtout=$$(gofmt -l .); if [ -n "$$fmtout" ]; then echo "gofmt needed:"; echo "$$fmtout"; exit 1; fi
	go vet ./...
	$(GOBIN)/golangci-lint run --allow-serial-runners ./...

fmt: ## format everything
	gofmt -w .

tools: ## install dev tools into GOPATH/bin
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

lab-up: ## start the censor lab (placeholder until TP-002)
	@echo "lab-up: the lab doesn't exist yet (TP-002)"; exit 1

lab-test: ## run the lab checks (placeholder until TP-002)
	@echo "lab-test: the lab doesn't exist yet (TP-002)"; exit 1

lab-down: ## stop the censor lab (placeholder until TP-002)
	@echo "lab-down: the lab doesn't exist yet (TP-002)"; exit 1
