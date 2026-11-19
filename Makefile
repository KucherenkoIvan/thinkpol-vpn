# thinkpol-vpn development targets. `make help` lists them.

# Every go command here, the dev tools' builds included, runs the toolchain
# go.mod's toolchain line names, whatever the host's default Go is: under
# GOTOOLCHAIN=auto that line is only a minimum, so a newer local Go would
# run as is, and govulncheck and the tests would see its standard library.
# `make GOTOOLCHAIN=...` still overrides it. Go drops the toolchain line
# when it equals the go line, so that line is the fallback: an empty
# GOTOOLCHAIN would mean auto again.
GO_TOOLCHAIN := $(shell sed -nE 's/^toolchain[[:space:]]+(go[0-9.]+).*/\1/p' go.mod)
ifeq ($(GO_TOOLCHAIN),)
GO_TOOLCHAIN := $(shell sed -nE 's/^go[[:space:]]+([0-9.]+).*/go\1/p' go.mod)
endif
ifeq ($(GO_TOOLCHAIN),)
$(error go.mod names no toolchain and no go version)
endif
export GOTOOLCHAIN := $(GO_TOOLCHAIN)

# Dev tools, pinned, installed per checkout into bin/tools (lint and proto
# install them on first use). Bumping a version or the toolchain reinstalls
# them all: govulncheck built by one Go fails on another's standard library.
GOLANGCI_LINT_VERSION := v2.14.0
BUF_VERSION := v1.73.0
PROTOC_GEN_GO_VERSION := v1.36.12
PROTOC_GEN_GO_GRPC_VERSION := v1.6.2
GOVULNCHECK_VERSION := v1.9.0

TOOLS := $(CURDIR)/bin/tools
TOOLS_STAMP := $(TOOLS)/.installed-$(GOTOOLCHAIN)-$(GOLANGCI_LINT_VERSION)-$(BUF_VERSION)-$(PROTOC_GEN_GO_VERSION)-$(PROTOC_GEN_GO_GRPC_VERSION)-$(GOVULNCHECK_VERSION)

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# The OSes the binary ships for: lint vets each, so OS-specific files are
# checked on any host.
LINT_GOOS := darwin linux windows
# Pure Go, no cgo (DESIGN.md "Repository layout").
NOCGO_PKGS := ./internal/dataplane/... ./internal/netmap/... ./internal/lists/... ./internal/shaping/...
# What must build for Android: the above minus the desktop-only packages.
DESKTOP_ONLY_RE := /internal/dataplane/(tun|egress|firewall)(/|$$)

# The branch the protobuf schemas must stay wire-compatible with.
BUF_BREAKING_AGAINST ?= rewrite

# cgo is off unless a target turns it on (test-race).
export CGO_ENABLED := 0

.PHONY: help build test test-race lint vulncheck nocgo proto-check fmt proto tools lab lab-up lab-test lab-test-default lab-test-long lab-harness lab-harness-hash lab-harness-cached lab-perf lab-gotest lab-test-rhythm-real lab-down lab-seccomp lab-seccomp-check

help: ## list targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-17s %s\n", $$1, $$2}'

build: ## build bin/thinkpol for this machine
	go build -trimpath -ldflags "-X main.version=$(VERSION)" -o bin/thinkpol ./cmd/thinkpol

test: ## unit tests (lab tests skip outside the lab)
	go test ./...

test-race: ## unit tests with the race detector (needs cgo)
	CGO_ENABLED=1 go test -race ./...

lint: $(TOOLS_STAMP) ## gofmt, then go vet + golangci-lint per OS (lab tests included), the Android build, the no-cgo check and vulncheck
	@python3 tickets/test_board.py -q 2>&1 | tail -1 | grep -qx OK || { python3 tickets/test_board.py; exit 1; }
	@goroot=$$(go env GOROOT) || exit 1; \
	out=$$("$$goroot/bin/gofmt" -l . 2>&1) || { echo "$$out"; exit 1; }; \
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
	@$(MAKE) --no-print-directory lab-seccomp-check
	@$(MAKE) --no-print-directory vulncheck

# govulncheck fetches the Go vulnerability database (vuln.go.dev) on every
# run, so lint needs the network; a scan takes seconds. It reports only
# vulnerabilities our code can reach, per OS we ship for (Android too).
vulncheck: $(TOOLS_STAMP) ## govulncheck per OS, Android included: fail on a known vulnerability in reachable code (needs the network)
	@for os in $(LINT_GOOS) android; do \
		echo "govulncheck, GOOS=$$os"; \
		GOOS=$$os GOARCH=$$([ $$os = android ] && echo arm64 || go env GOARCH) $(TOOLS)/govulncheck ./... || exit 1; \
	done

nocgo: ## fail if the data plane, the map or the lists depend on cgo
	@for os in $(LINT_GOOS) android; do \
		out=$$(CGO_ENABLED=1 GOOS=$$os go list -deps -f '{{if and (not .Standard) .CgoFiles}}{{.ImportPath}}{{end}}' $(NOCGO_PKGS)) || exit 1; \
		if [ -n "$$out" ]; then echo "cgo in pure Go packages (GOOS=$$os):"; echo "$$out"; exit 1; fi; \
	done
	@echo "no cgo in $(NOCGO_PKGS)"

fmt: ## format everything
	"$$(go env GOROOT)/bin/gofmt" -w .

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
	GOBIN=$(TOOLS) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	touch $@

# The lab (lab/README.md): Docker only, every lab a Compose project of its
# own, named after this checkout and the run, so several checkouts, and
# several runs from one checkout, can run labs at once.
LABCTL := go run -trimpath -buildvcs=false ./lab/labctl
# labctl as make lab-test and make lab-gotest build it. The node phase's
# cache of passes keys on labctl's own binary, so both build it alike, and
# without the VCS stamp, which every commit would change.
LABCTL_BUILD := go build -trimpath -buildvcs=false -o
LAB_TIMEOUT ?= 60m
# Packages make lab-test runs in nodes at once. Fixed, not scaled by load:
# tests must hold up under other runs' load anyway (lab/README.md). The
# lab/ test phase, this phase and the long stream run at the same time and
# draw from the same lab slot cap.
LAB_P ?= 4
# The default stream's budget: wall time from the stream's start, lab
# setup included (lab/README.md, "Streams"). A slower machine sets its own
# in its environment.
LAB_BUDGET ?= 15m
# The tests under lab/ the long stream runs: exactly those that call
# lab.LongTest or lab.SplitStreams (TestLongTestsNamed checks it). Today
# the censor matrix, whose held cells are the long stream's (lab/README.md,
# "Streams").
LAB_LONG_TESTS := ^TestCensorMatrix$$

# The harness's own lab tests (named TestHarness…) check the lab itself
# (isolation, sealing, ownership, subnets, binaries), not the product.
# make lab-test runs them only when what they check changed: a pass is
# remembered under the hash of LAB_HARNESS_FILES (the non-test Go files
# under lab/: the harness, its tools, the censor; the harness tests and the
# helpers they reach, all in lab/harness*_test.go, which
# TestTheHarnessHashCoversWhatItsTestsReach checks; lab/ip's tests, which
# TestHarnessAnotherRun… runs in its nodes; the image, the seccomp profile,
# go.mod and go.sum) and the Go, Docker, Docker kernel and Compose
# versions, in LAB_HARNESS_CACHE (shared by checkouts: the hash names the
# content, not the checkout). A run in which a harness test skipped isn't
# remembered, nor one during which the hash changed: the run builds the lab
# binaries from the checkout as it goes.
LAB_HARNESS_RUN := ^TestHarness
LAB_HARNESS_CACHE ?= $(HOME)/.cache/thinkpol-lab/harness
LAB_HARNESS_GOTEST = go test -tags lab -count=1 -timeout $(LAB_TIMEOUT) -run '$(LAB_HARNESS_RUN)' ./lab
LAB_HARNESS_FILES = $(shell find lab -name '*.go' ! -name '*_test.go' | LC_ALL=C sort) $(sort $(wildcard lab/harness*_test.go)) $(sort $(wildcard lab/ip/*_test.go)) lab/Dockerfile lab/seccomp.json go.mod go.sum
# Hashed from a file, not a pipe: a read that fails inside a pipe fails
# only the pipe's subshell, and the partial input would still hash.
LAB_HARNESS_HASH = versions=$$(go version && docker version --format '{{.Server.Version}}' && docker info --format '{{.KernelVersion}}' && docker compose version --short) || exit 1; \
	tmp=$$(mktemp) || exit 1; trap 'rm -f "$$tmp"' EXIT; \
	{ echo "$$versions"; for f in $(LAB_HARNESS_FILES); do echo "== $$f" && cat "$$f" || exit 1; done; } > "$$tmp" || exit 1; \
	git hash-object "$$tmp"

lab: lab-test ## the lab suite, ending in the censor matrix (lab/RESULTS.md)

lab-up: ## start the standard topology for this checkout, for poking around
	$(LABCTL) up

lab-test: ## both streams at once, then tear down: the default stream (lab tests, every package's tests in a lab node, lab-harness if the harness changed; under LAB_BUDGET) and the long stream (COUNT=n: node phase repeated, uncached)
lab-test-default: ## the default stream alone, under LAB_BUDGET (RESULTS.md needs both streams: make lab-test)
lab-test-long: ## the long stream alone: the lab tests that wait minutes on real timers
lab-test: LAB_STREAMS = default long
lab-test-default: LAB_STREAMS = default
lab-test-long: LAB_STREAMS = long

# The streams in LAB_STREAMS run at once (lab/README.md, "Streams"). Each
# phase writes its own exit status: sh has no pipefail. Every phase shares
# one run id (THINKPOL_LAB_RUN, in their labs' names), and the clean-up,
# on Ctrl-C too, removes that run's labs only: another run's from this
# checkout (a lab-gotest beside it, another lab-test) stay. ./lab's test
# binary is built once, at the start, and both streams and the assembly of
# RESULTS.md run that binary, as go test -json would (go tool test2json),
# so a checkout changed mid-run can't write RESULTS.md; the shares carry
# the commit it was built from (THINKPOL_LAB_COMMIT, taken once the build
# is done, "-dirty" with uncommitted changes). On Ctrl-C or a
# TERM, the phases' processes get a TERM (a script's background jobs
# ignore SIGINT), and once they are gone (2 minutes at most: labctl
# gotest tears its labs down first), the run's labs are removed. The
# recipe is one line with $(MAKE) in it, so make -n runs it: don't. The
# other ./lab/...
# packages run under go test. labctl testjson prints what go test without
# -v would have and keeps each test's time for the budget's report; its
# exit status fails its phase, and its TMPDIR (only its: the lab slot
# cap's locks live in TMPDIR) is the run's directory, so the long logs it
# spills to files go with the run on an abort. Exit
# status: 1 when a test or the tear-down failed, 3 when everything passed
# but the default stream ran over LAB_BUDGET (make itself exits 2 either
# way and quotes the recipe's status, "Error 3"); the last line says which.
lab-test lab-test-default lab-test-long:
	@start=$$(date +%s); run=; labctl=; \
	tmp=$$(mktemp -d) || exit 1; \
	trap 'rc=$$?; if [ -n "$$run" ] && [ -z "$$THINKPOL_LAB_KEEP" ]; then "$$labctl" down -run "$$run" || rc=1; fi; rm -rf "$$tmp"; exit $$rc' EXIT; \
	tree() { for c in $$(pgrep -P "$$1"); do echo "$$c"; tree "$$c"; done; }; \
	stop() { trap '' INT TERM; pids=$$(tree $$$$); [ -z "$$pids" ] || kill -TERM $$pids 2>/dev/null; wait; \
		n=0; for p in $$pids; do while kill -0 "$$p" 2>/dev/null && [ $$n -lt 120 ]; do sleep 1; n=$$((n+1)); done; done; exit "$$1"; }; \
	trap 'stop 130' INT; trap 'stop 143' TERM; \
	labctl=$$tmp/labctl; $(LABCTL_BUILD) "$$labctl" ./lab/labctl || exit 1; \
	"$$labctl" budget -check -budget='$(LAB_BUDGET)' || exit 1; \
	go test -tags lab -c -o "$$tmp/lab.test" ./lab || exit 1; \
	commit=$$(git rev-parse HEAD) && dirty=$$(git status --porcelain) || exit 1; \
	export THINKPOL_LAB_COMMIT=$$commit$${dirty:+-dirty}; \
	labpkg=$$(go list -tags lab ./lab) && others=$$(go list -tags lab ./lab/... | grep -vx "$$labpkg") || exit 1; \
	"$$labctl" down -stale || exit 1; \
	run=$$("$$labctl" run-id) || { run=; exit 1; }; export THINKPOL_LAB_RUN=$$run THINKPOL_LAB_RESULTS_DIR=$$tmp; \
	phases=; failed=; both=; \
	case " $(LAB_STREAMS) " in *" default "*) case " $(LAB_STREAMS) " in *" long "*) both=1;; esac;; esac; \
	case " $(LAB_STREAMS) " in *" default "*) \
		( { ( cd lab && THINKPOL_LAB_STREAM=default exec go tool test2json -t -p "$$labpkg" "$$tmp/lab.test" -test.v=test2json -test.paniconexit0 -test.count=1 -test.timeout=$(LAB_TIMEOUT) -test.skip='$(LAB_HARNESS_RUN)' ) 2>&1; echo $$? > "$$tmp/lab.status"; } | { TMPDIR="$$tmp" "$$labctl" testjson -times "$$tmp/lab.times" 2>&1; echo $$? > "$$tmp/lab.testjson"; } | awk '{print "[lab]  " $$0; fflush()}' ) & lab=$$!; \
		( { THINKPOL_LAB_STREAM=default go test -tags lab -json -count=1 -timeout $(LAB_TIMEOUT) -skip '$(LAB_HARNESS_RUN)' $$others 2>&1; echo $$? > "$$tmp/labpkgs.status"; } | { TMPDIR="$$tmp" "$$labctl" testjson -times "$$tmp/labpkgs.times" 2>&1; echo $$? > "$$tmp/labpkgs.testjson"; } | awk '{print "[lab]  " $$0; fflush()}' ) & labpkgs=$$!; \
		( { "$$labctl" gotest -p $(LAB_P) -times "$$tmp/node.times" $(if $(COUNT),-count $(COUNT)) ./...; echo $$? > "$$tmp/node.status"; } 2>&1 | awk '{print "[node] " $$0; fflush()}' ) & node=$$!; \
		( { $(MAKE) --no-print-directory lab-harness-cached LABCTL="$$labctl" LAB_HARNESS_TIMES="$$tmp/harness.times"; echo $$? > "$$tmp/harness.status"; } 2>&1 | awk '{print "[harness] " $$0; fflush()}' ) & harness=$$!; \
		phases="lab labpkgs node harness";; \
	esac; \
	case " $(LAB_STREAMS) " in *" long "*) \
		( ( { ( cd lab && THINKPOL_LAB_STREAM=long exec go tool test2json -t -p "$$labpkg" "$$tmp/lab.test" -test.v=test2json -test.paniconexit0 -test.count=1 -test.timeout=$(LAB_TIMEOUT) -test.run='$(LAB_LONG_TESTS)' ) 2>&1; echo $$? > "$$tmp/long.status"; } | { TMPDIR="$$tmp" "$$labctl" testjson -times "$$tmp/long.times" 2>&1; echo $$? > "$$tmp/long.testjson"; } | awk '{print "[long] " $$0; fflush()}' ) & \
		  ( { THINKPOL_LAB_STREAM=long go test -tags lab -json -count=1 -timeout $(LAB_TIMEOUT) -run '$(LAB_LONG_TESTS)' $$others 2>&1; echo $$? > "$$tmp/longpkgs.status"; } | { TMPDIR="$$tmp" "$$labctl" testjson -times "$$tmp/longpkgs.times" 2>&1; echo $$? > "$$tmp/longpkgs.testjson"; } | awk '{print "[long] " $$0; fflush()}' ) & \
		  wait; "$$labctl" budget -stream long -since $$start "$$tmp/long.times" "$$tmp/longpkgs.times" || echo 1 > "$$tmp/long.status" ) & \
		phases="$$phases long longpkgs";; \
	esac; \
	case " $(LAB_STREAMS) " in *" default "*) \
		wait $$lab $$labpkgs $$node $$harness; \
		"$$labctl" budget -stream default -since $$start -budget='$(LAB_BUDGET)' -over "$$tmp/over" "$$tmp/lab.times" "$$tmp/labpkgs.times" "$$tmp/node.times" "$$tmp/harness.times" || [ -s "$$tmp/over" ] || failed="$$failed budget-check";; \
	esac; \
	wait; \
	for f in $$phases; do \
		if [ -f "$$tmp/$$f.status" ]; then \
			[ "$$(cat "$$tmp/$$f.status")" = 0 ] || failed="$$failed $$f"; \
		else \
			echo "lab-test: the $$f phase died without a status" >&2; failed="$$failed $$f"; \
		fi; \
		case $$f in node|harness) ;; *) [ "$$(cat "$$tmp/$$f.testjson" 2>/dev/null)" = 0 ] || { echo "lab-test: the $$f phase's labctl testjson failed" >&2; failed="$$failed $$f-testjson"; };; esac; \
	done; \
	flakes=$$(LC_ALL=C sort -u "$$tmp"/known-flakes-*.txt 2>/dev/null | awk 'NF { n++; s = s (n > 1 ? ", " : "") $$0 } END { if (n) printf "KNOWN FLAKES: %d (%s)", n, s }'); \
	case "$$both" in 1) \
		if ( cd lab && THINKPOL_LAB_STREAM= exec "$$tmp/lab.test" -test.v -test.count=1 -test.run='^TestAssembleCensorMatrix$$' ) > "$$tmp/assemble.out" 2>&1 \
		&& grep -q '^--- PASS: TestAssembleCensorMatrix ' "$$tmp/assemble.out"; then \
			echo "lab-test: lab/RESULTS.md assembled from both streams"; \
		else \
			cat "$$tmp/assemble.out"; echo "lab-test: lab/RESULTS.md not assembled" >&2; failed="$$failed RESULTS.md"; \
		fi;; \
	*) echo "lab-test: lab/RESULTS.md not written: the censor matrix needs both streams (make lab-test)";; \
	esac; \
	if [ -z "$$THINKPOL_LAB_KEEP" ] && ! "$$labctl" down -run "$$run"; then failed="$$failed tear-down"; fi; run=; \
	over=$$(cat "$$tmp/over" 2>/dev/null); \
	if [ -n "$$failed" ]; then \
		echo "lab-test: FAILED:$$failed$${over:+; also OVER BUDGET ($$over)}$${flakes:+; $$flakes}"; exit 1; \
	elif [ -n "$$over" ]; then \
		echo "lab-test: tests passed, OVER BUDGET ($$over)$${flakes:+; $$flakes}"; exit 3; \
	fi; \
	echo "lab-test: passed$${flakes:+; $$flakes}"


lab-harness: ## the lab harness's own tests (TestHarness…: isolation, sealing, ownership, subnets), each starting labs
	$(LAB_HARNESS_GOTEST)

# The hash lab-harness-cached keys its stamp by.
lab-harness-hash:
	@$(LAB_HARNESS_HASH)

# lab-harness unless it passed before on the same harness (a phase of
# make lab-test's default stream). With LAB_HARNESS_TIMES set (make
# lab-test sets it, and LABCTL to its own build), it runs go test -json
# through labctl testjson -v, which prints what go test -v would and
# writes each test's time to that file, for the budget's report (its
# TMPDIR that file's directory); a cached harness writes an empty one.
lab-harness-cached:
	@hash=$$($(LAB_HARNESS_HASH)) && [ -n "$$hash" ] || { echo "lab-harness: can't hash the harness" >&2; exit 1; }; \
	stamp="$(LAB_HARNESS_CACHE)/$$hash"; \
	if [ -e "$$stamp" ]; then echo "lab-harness: passed before on harness $$hash, not run again"; $(if $(LAB_HARNESS_TIMES),: > "$(LAB_HARNESS_TIMES)";) exit 0; fi; \
	echo "lab-harness: harness $$hash not passed before, running it"; \
	out=$$(mktemp) || exit 1; trap 'rm -f "$$out" "$$out.status" "$$out.testjson"' EXIT; \
	{ $(LAB_HARNESS_GOTEST) -v $(if $(LAB_HARNESS_TIMES),-json); echo $$? > "$$out.status"; } 2>&1 $(if $(LAB_HARNESS_TIMES),| { TMPDIR="$(dir $(LAB_HARNESS_TIMES))" $(LABCTL) testjson -v -times "$(LAB_HARNESS_TIMES)" 2>&1; echo $$? > "$$out.testjson"; }) | tee "$$out"; \
	[ "$$(cat "$$out.status" 2>/dev/null)" = 0 ] || exit 1; \
	$(if $(LAB_HARNESS_TIMES),[ "$$(cat "$$out.testjson" 2>/dev/null)" = 0 ] || { echo "lab-harness: labctl testjson failed" >&2; exit 1; }; )\
	if grep -E -q -e '^ *--- SKIP: TestHarness' -e '^testing: warning: no tests to run' "$$out"; then \
		echo "lab-harness: passed, but a harness test skipped: not remembered, the next make lab-test runs it again"; exit 0; \
	fi; \
	after=$$($(LAB_HARNESS_HASH)) && [ -n "$$after" ] || { echo "lab-harness: can't hash the harness after the run" >&2; exit 1; }; \
	if [ "$$after" != "$$hash" ]; then \
		echo "lab-harness: passed, but the harness changed during the run ($$hash, now $$after): not remembered, the next make lab-test runs it again"; exit 0; \
	fi; \
	mkdir -p "$(LAB_HARNESS_CACHE)" && touch "$$stamp"

# Performance gates: tests that check THINKPOL_LAB_PERF and are named
# Test…Throughput, in these packages (a new one adds its package here).
LAB_PERF_PKGS ?= ./internal/agent/supervisor
LAB_PERF_RUN ?= Throughput$$

lab-perf: ## performance gates, alone on the host: waits for every other lab run, then measures (THINKPOL_LAB_PERF=1)
	$(LABCTL) gotest -perf -v -p 1 -run '$(LAB_PERF_RUN)' $(LAB_PERF_PKGS)

# lab-gotest's test binaries' -timeout: LAB_TIMEOUT when the environment
# or the command line sets it; otherwise 60m with COUNT=n, and labctl's
# defaults without (lab.DefaultTestTimeout in a node, 60m on the host).
LAB_GOTEST_TIMEOUT = $(if $(filter file,$(origin LAB_TIMEOUT)),$(if $(COUNT),60m),$(LAB_TIMEOUT))

lab-gotest: export LAB_RUN = $(RUN)
lab-gotest: export LAB_SKIP = $(SKIP)
lab-gotest: ## run PKG's tests inside a lab node with THINKPOL_LAB=1, its lab-tagged tests on the host; fails if all skip (PKG=./internal/... required, RUN=regexp SKIP=regexp COUNT=n LAB_TIMEOUT=d)
	$(if $(PKG),,$(error lab-gotest needs PKG, e.g. PKG=./internal/dataplane/netcfg/...; make lab-test runs every package))
	@tmp=$$(mktemp -d) || exit 1; trap 'rm -rf "$$tmp"' EXIT; \
	$(LABCTL_BUILD) "$$tmp/labctl" ./lab/labctl || exit 1; \
	"$$tmp/labctl" gotest -v -tagged -fail-skipped -run "$$LAB_RUN" -skip "$$LAB_SKIP" $(if $(COUNT),-count $(COUNT)) $(if $(LAB_GOTEST_TIMEOUT),-timeout $(LAB_GOTEST_TIMEOUT)) $(PKG)

# The lab's thinkpol runs WireGuard's timers sped up (lab/README.md,
# "WireGuard's timers"); this runs the censor matrix's rhythm cells, and
# their rows' off cells, at real time, for changes to transport shaping or
# the rhythm rules; a full lab at real time is
# THINKPOL_LAB_WG_TIMER_SCALE=1 make lab-test.
lab-test-rhythm-real: export THINKPOL_LAB_WG_TIMER_SCALE = 1
lab-test-rhythm-real: ## the censor matrix's wireguard-rhythm cells with WireGuard's real timers (10 to 15 minutes)
	$(LABCTL) gotest -v -tagged -fail-skipped -run 'TestCensorMatrix/^(udp|reality)$$/^(off|wireguard-rhythm)$$' ./lab

lab-seccomp: ## regenerate lab/seccomp.json from the moby/profiles/seccomp lab/seccompgen pins (needs the network once)
	cd lab/seccompgen && go run . -o ../seccomp.json

# A hand edit of lab/seccomp.json (a syscall added to an allow rule) passes
# every test that reads it; only regenerating it shows the drift.
lab-seccomp-check: ## fail if lab/seccomp.json isn't what make lab-seccomp generates (needs the network once, as vulncheck does)
	@tmp=$$(mktemp) || exit 1; \
	trap 'rm -f "$$tmp"' EXIT; \
	( cd lab/seccompgen && go run . -o "$$tmp" ) >/dev/null || exit 1; \
	cmp -s "$$tmp" lab/seccomp.json || { echo "lab/seccomp.json differs from what make lab-seccomp generates: run make lab-seccomp, don't edit the file"; exit 1; }

lab-down: ## remove every lab this checkout started
	$(LABCTL) down
