# thinkpol-vpn development targets. `make help` lists them.

# Dev tools, pinned, installed per checkout into bin/tools (lint and proto
# install them on first use). Bumping a version reinstalls them all.
GOLANGCI_LINT_VERSION := v2.14.0
BUF_VERSION := v1.73.0
PROTOC_GEN_GO_VERSION := v1.36.12
PROTOC_GEN_GO_GRPC_VERSION := v1.6.2

TOOLS := $(CURDIR)/bin/tools
TOOLS_STAMP := $(TOOLS)/.installed-$(GOLANGCI_LINT_VERSION)-$(BUF_VERSION)-$(PROTOC_GEN_GO_VERSION)-$(PROTOC_GEN_GO_GRPC_VERSION)

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# The OSes the binary ships for: lint vets each, so OS-specific files are
# checked on any host.
LINT_GOOS := darwin linux windows
# Pure Go, no cgo (DESIGN.md "Repository layout").
NOCGO_PKGS := ./internal/dataplane/... ./internal/netmap/... ./internal/lists/...
# What must build for Android: the above minus the desktop-only packages.
DESKTOP_ONLY_RE := /internal/dataplane/(tun|egress|firewall)(/|$$)

# The branch the protobuf schemas must stay wire-compatible with.
BUF_BREAKING_AGAINST ?= rewrite

# cgo is off unless a target turns it on (test-race).
export CGO_ENABLED := 0

.PHONY: help build test test-race lint nocgo proto-check fmt proto tools lab lab-up lab-test lab-gotest lab-down

help: ## list targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-14s %s\n", $$1, $$2}'

build: ## build bin/thinkpol for this machine
	go build -trimpath -ldflags "-X main.version=$(VERSION)" -o bin/thinkpol ./cmd/thinkpol

test: ## unit tests (lab tests skip outside the lab)
	go test ./...

test-race: ## unit tests with the race detector (needs cgo)
	CGO_ENABLED=1 go test -race ./...

lint: $(TOOLS_STAMP) ## gofmt, then go vet + golangci-lint per OS (lab tests included), the Android build and the no-cgo check
	@out=$$(gofmt -l . 2>&1) || { echo "$$out"; exit 1; }; \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	@for os in $(LINT_GOOS); do \
		echo "go vet + golangci-lint, GOOS=$$os"; \
		GOOS=$$os go vet -tags lab ./... || exit 1; \
		GOOS=$$os $(TOOLS)/golangci-lint run --build-tags lab --allow-serial-runners ./... || exit 1; \
	done
	@echo "build for android/arm64"
	@pkgs=$$(GOOS=android GOARCH=arm64 go list $(NOCGO_PKGS)) || exit 1; \
	pkgs=$$(echo "$$pkgs" | grep -vE '$(DESKTOP_ONLY_RE)'); \
	if [ -z "$$pkgs" ]; then echo "no packages to build for android"; exit 1; fi; \
	GOOS=android GOARCH=arm64 go build $$pkgs
	@$(MAKE) --no-print-directory nocgo
	@$(MAKE) --no-print-directory proto-check

nocgo: ## fail if the data plane, the map or the lists depend on cgo
	@for os in $(LINT_GOOS) android; do \
		out=$$(CGO_ENABLED=1 GOOS=$$os go list -deps -f '{{if and (not .Standard) .CgoFiles}}{{.ImportPath}}{{end}}' $(NOCGO_PKGS)) || exit 1; \
		if [ -n "$$out" ]; then echo "cgo in pure Go packages (GOOS=$$os):"; echo "$$out"; exit 1; fi; \
	done
	@echo "no cgo in $(NOCGO_PKGS)"

fmt: ## format everything
	gofmt -w .

proto-check: $(TOOLS_STAMP) ## buf lint, proto/gen up to date, no wire-breaking change against $(BUF_BREAKING_AGAINST)
	@if [ -z "$$(find proto -name '*.proto' -not -path 'proto/gen/*')" ]; then echo "proto: no .proto files yet"; exit 0; fi; \
	(cd proto && $(TOOLS)/buf lint) || exit 1; \
	tmp=$$(mktemp -d) || exit 1; trap 'rm -rf "$$tmp"' EXIT; \
	(cd proto && PATH="$(TOOLS):$$PATH" $(TOOLS)/buf generate -o "$$tmp") || exit 1; \
	if ! diff -r "$$tmp/gen" proto/gen >/dev/null; then echo "proto/gen is stale, run make proto:"; diff -r "$$tmp/gen" proto/gen | head -20; exit 1; fi; \
	if git ls-tree -r --name-only "$(BUF_BREAKING_AGAINST)" -- proto 2>/dev/null | grep -v '^proto/gen/' | grep -q '\.proto$$'; then \
		echo "buf breaking against $(BUF_BREAKING_AGAINST)"; \
		(cd proto && $(TOOLS)/buf breaking --against "$$(git rev-parse --path-format=absolute --git-common-dir)#ref=$(BUF_BREAKING_AGAINST),subdir=proto") || exit 1; \
	else echo "buf breaking: $(BUF_BREAKING_AGAINST) has no schemas yet, skipped"; fi

proto: $(TOOLS_STAMP) ## lint the protobuf schemas and regenerate proto/gen
	@if [ -z "$$(find proto -name '*.proto' -not -path 'proto/gen/*')" ]; then echo "proto: no .proto files yet"; exit 0; fi; \
	cd proto && $(TOOLS)/buf lint && PATH="$(TOOLS):$$PATH" $(TOOLS)/buf generate

tools: $(TOOLS_STAMP) ## install the pinned dev tools into bin/tools

$(TOOLS_STAMP):
	rm -rf $(TOOLS) && mkdir -p $(TOOLS)
	GOBIN=$(TOOLS) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	GOBIN=$(TOOLS) go install github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)
	GOBIN=$(TOOLS) go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	GOBIN=$(TOOLS) go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)
	touch $@

# The lab (lab/README.md): Docker only, every lab a Compose project of its
# own, named after this checkout, so several checkouts can run labs at once.
LABCTL := go run ./lab/labctl
LAB_TIMEOUT ?= 20m

lab: lab-test ## the lab suite (TP-024 makes it run the censor matrix)

lab-up: ## start the standard topology for this checkout, for poking around
	$(LABCTL) up

lab-test: ## lab tests (each starts its own lab) + every package's tests inside a lab node; tears down after
	@status=0; \
	go test -tags lab -count=1 -timeout $(LAB_TIMEOUT) ./lab/... || status=1; \
	$(LABCTL) gotest ./... || status=1; \
	$(LABCTL) down -tests; \
	exit $$status

lab-gotest: ## run PKG's tests inside a lab node with THINKPOL_LAB=1 (PKG=./internal/... RUN=regexp)
	$(LABCTL) gotest -v $(if $(RUN),-run '$(RUN)') $(or $(PKG),./...)

lab-down: ## remove every lab this checkout started
	$(LABCTL) down
