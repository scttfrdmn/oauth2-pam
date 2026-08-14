.PHONY: build test test-unit test-cbridge test-cbridge-mutations test-integration test-integration-mutations verify-linux install clean lint fmt vet tidy help

# Build variables
BINARY_DIR := bin
PAM_MODULE := oauth2_pam.so
BROKER_BINARY := oauth2-pam-broker
ADMIN_BINARY := oauth2-pam-admin
ENROLL_BINARY := oauth2-pam-enroll

# Version information
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go build flags
GO_BUILD_FLAGS := -ldflags="-s -w -X main.version=$(VERSION) -X main.buildDate=$(BUILD_DATE) -X main.gitCommit=$(GIT_COMMIT)" -trimpath
GO_TEST_FLAGS := -race -coverprofile=coverage.out

# ---------------------------------------------------------------------------
# PAM module build (plain C, no Go — issue #65)
#
# The module is a Linux-PAM module written in C, compiled by cc directly. It used
# to be built with `go build -buildmode=c-shared ./cmd/pam-module`, which linked
# the whole Go runtime — goroutine scheduler, garbage collector and, decisively,
# the runtime's signal handlers — into sshd's address space for the sake of two Go
# files that contained no logic at all. Every PAM entry point is and always was in
# cgo_bridge_linux.c. So the Go shim is gone and this is the compile line.
#
# The flags below moved here from the #cgo directives in the deleted
# cmd/pam-module/pam_linux.go. They are the only hardening this artifact gets, and
# it is an artifact loaded into a process that runs as root while holding a
# pre-auth network connection — so the reasoning travels with them rather than
# being rediscovered:
#
#   -Werror, on a *release* artifact, is a deliberate risk: a future compiler that
#   warns about untouched code turns a build into a failure. It is taken because
#   the alternative is a warning nobody reads in a module that runs as root, and
#   because CI builds this on a pinned image. The same C compiles warning-clean
#   under the same flags in test/cbridge/, which is why turning them on costs
#   nothing today and is worth doing before it does.
#
#   -D_FORTIFY_SOURCE=2, not 3. Level 3 needs gcc 12 and glibc 2.35; on an older
#   toolchain glibc's features.h answers with a #warning, which -Werror above
#   would turn into a build failure on exactly the enterprise distributions this
#   module is meant to install on. -U first because Debian's and Ubuntu's gcc
#   already define it, and a redefinition is itself a warning.
#
#   -fstack-clash-protection is x86-64 and aarch64 only; both are the release
#   targets. -fcf-protection is deliberately absent: it is x86-only and would
#   break the aarch64 build outright rather than warn.
#
#   No -fPIE/-pie: this links a shared object, which is already
#   position-independent, and -pie on a .so is a link error. -fPIC is what a .so
#   needs and is passed explicitly, since cc does not imply it.
#
# Two dynamic flags the c-shared build used to set are gone, and neither is a lost
# mitigation. `go build -buildmode=c-shared` also passed -Bsymbolic and marked the
# object NODELETE. SYMBOLIC has nothing left to do here: every function in
# cgo_bridge_linux.c except the six pam_sm_* entry points is static, so there are no
# internal references for the dynamic linker to resolve elsewhere. That claim was
# false when it was written and is now true — eleven functions were declared in
# cgo_bridge.h and so exported, with internal call sites resolving through the PLT
# against the global scope, which is exactly what SYMBOLIC prevents (#97). They are
# static, and verify-pam-symbols.sh now asserts what is *not* exported as well as
# what is, so the claim cannot quietly stop being true again. NODELETE existed
# because the Go runtime cannot survive being unloaded — it pinned the module, and
# 1.2 MB of scheduler with it, in sshd for the life of the process. A plain C module
# has no such problem, so letting PAM dlclose it again is the correct behaviour.
# BIND_NOW and full RELRO, which are the ones that matter for a writable GOT in a
# root process, are set explicitly above and survive.
#
# Verify the mitigations actually took on the built .so rather than trusting this
# comment:
#
#	readelf -lWd bin/oauth2_pam.so | grep -E 'GNU_RELRO|BIND_NOW|FLAGS'
#	nm -D --undefined-only bin/oauth2_pam.so | grep __stack_chk_fail
CC ?= cc
PAM_SRC := cmd/pam-module/cgo_bridge_linux.c
PAM_CFLAGS := -std=c11 -D_GNU_SOURCE -Icmd/pam-module -I/usr/include/security \
	-Wall -Wextra -Wconversion -Wformat -Wformat-security -Werror \
	-fstack-protector-strong -fstack-clash-protection -fno-common \
	-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -O2
PAM_LDFLAGS := -shared -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
PAM_LDLIBS := -lpam -ljson-c

# Version stamping, which -ldflags used to do and cannot any more: there is no Go
# in this artifact, so `-X main.version=...` had nothing to set. PAM_MODULE_VERSION
# and PAM_MODULE_BUILD in cgo_bridge.h are what the module logs at the start of
# every authentication, and each has a literal fallback so a bare
# `cc cgo_bridge_linux.c` with no -D still compiles and still reports something
# truthful about itself.
PAM_VERSION_FLAGS := -DPAM_MODULE_VERSION='"$(VERSION)"' \
	-DPAM_MODULE_BUILD='"$(GIT_COMMIT) $(BUILD_DATE)"'

# Default target
all: build

## Build all binaries
build: build-broker build-pam build-admin build-enroll

## Build authentication broker daemon
build-broker:
	@echo "Building authentication broker..."
	@mkdir -p $(BINARY_DIR)
	go build $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(BROKER_BINARY) ./cmd/broker

## Build PAM module (Linux only — needs a C toolchain, Linux-PAM headers, json-c)
##
## The guard asks the C toolchain, not `go env GOOS`: there is no Go in this
## artifact any more, so what has to exist is a compiler that can find
## security/pam_appl.h and json-c/json.h. uname is the cheap version of that
## question and the one that names the actual obstacle — libpam does not exist on
## macOS at all, so no amount of toolchain will do.
build-pam:
	@if [ "$$(uname -s)" != "Linux" ]; then \
		echo "build-pam: skipped — the PAM module needs a Linux C toolchain"; \
		echo "  (Linux-PAM headers and json-c, neither of which exists on this"; \
		echo "  platform). Build it in a Linux container:"; \
		echo "    make docker-build-pam"; \
		exit 1; \
	fi
	@echo "Building PAM module..."
	@mkdir -p $(BINARY_DIR)
	$(CC) $(PAM_CFLAGS) $(PAM_VERSION_FLAGS) -fPIC $(PAM_LDFLAGS) \
		-o $(BINARY_DIR)/$(PAM_MODULE) $(PAM_SRC) $(PAM_LDLIBS)
	@echo "Verifying PAM entry points are present..."
	@# Per symbol, and a build host without nm fails here rather than passing
	@# quietly. The same script runs in release.yml and in the installer, so a
	@# module that gets past one of them gets past all three for the same reason.
	@scripts/verify-pam-symbols.sh $(BINARY_DIR)/$(PAM_MODULE)

## Build the PAM module in a Linux container (works from macOS)
##
## debian:stable-slim rather than a Go image: the module is C, and the toolchain it
## needs is gcc plus two -dev packages. binutils comes along because
## verify-pam-symbols.sh refuses to pass without nm — a build host that cannot
## answer "are the entry points there" has not answered it.
docker-build-pam:
	@echo "Building PAM module in a Linux container..."
	@mkdir -p $(BINARY_DIR)
	docker run --rm -v "$(PWD)":/src -w /src debian:stable-slim sh -c '\
		apt-get update -qq && \
		apt-get install -y -qq --no-install-recommends \
			gcc libc6-dev libpam0g-dev libjson-c-dev binutils make >/dev/null && \
		make build-pam VERSION=$(VERSION) GIT_COMMIT=$(GIT_COMMIT) BUILD_DATE=$(BUILD_DATE)'

## Build admin CLI tool
build-admin:
	@echo "Building admin CLI..."
	@mkdir -p $(BINARY_DIR)
	go build $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(ADMIN_BINARY) ./cmd/oauth2-pam-admin

## Build enrollment CLI tool
build-enroll:
	@echo "Building enrollment CLI..."
	@mkdir -p $(BINARY_DIR)
	go build $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(ENROLL_BINARY) ./cmd/oauth2-pam-enroll

## Run all tests
test:
	@echo "Running tests..."
	go test $(GO_TEST_FLAGS) ./...

## Run unit tests only
test-unit:
	@echo "Running unit tests..."
	go test $(GO_TEST_FLAGS) ./pkg/... ./internal/...

## Run the C unit tests for the PAM module bridge
##
## `go test ./...` cannot see this code at all: the bridge is C, and on macOS
## cmd/pam-module is not even compiled. These cover the boundaries the container
## harness cannot provoke — a reply exactly the size of the buffer, a broker that
## accepts a connection and then goes silent, a broker that hangs up mid-request.
test-cbridge:
	@echo "Running C bridge tests..."
	test/cbridge/run.sh

## Check that the C bridge tests would catch the defects they were written for
##
## A green suite proves the code does what the tests say; it does not prove the
## tests would notice if it stopped. This reintroduces each fixed bridge defect
## in turn in a copy of the source under $$TMPDIR and asserts the suite
## fails. An uncaught mutation means that regression test is decoration.
test-cbridge-mutations:
	@echo "Running C bridge mutation check..."
	test/cbridge/mutations.sh

## Run the container integration harness (real sshd + PAM vs a real broker)
test-integration:
	@echo "Running container integration harness..."
	test/integration/run-tests.sh

## Check that the harness still catches the v0.1.x auth bypass
##
## The harness's most important claim is a negative one — an unapproved device
## flow is not a login — and negative assertions are the ones that rot into
## passing for the wrong reason. This rebuilds the module with the bypass
## reintroduced and insists the harness refuses the login.
test-integration-mutations:
	@echo "Running container harness mutation check..."
	test/integration/mutations.sh

## Run the Linux vet/test/lint sweep in a container, cgo packages included
##
## On macOS the module cannot be compiled at all. Since #65 it is not a Go package
## either, so no Go command touches it on any platform — this target compiles it and
## runs the C suite explicitly, because otherwise a green sweep would say nothing at
## all about the most security-sensitive code here. Answers "does the Linux build
## compile and pass"; use test-integration to answer "does a login work".
verify-linux:
	@echo "Building the verification image..."
	@docker build -q -f test/docker/Dockerfile.verify -t oauth2-pam-verify . >/dev/null
	@echo "Running vet, tests and lint under Linux..."
	docker run --rm \
		-v "$(PWD)":/src \
		-v oauth2-pam-verify-gocache:/root/.cache/go-build \
		-v oauth2-pam-verify-gomod:/go/pkg/mod \
		oauth2-pam-verify \
		sh -c 'go build ./... && go vet ./... && go test -race ./... && golangci-lint run ./... \
			&& make build-pam && test/cbridge/run.sh'

## Install binaries to system locations
install: build
	@echo "Installing binaries..."
	@# The PAM module directory is asked for, not assumed. This target hardcoded
	@# /lib/security, which is right on RHEL and wrong on Debian/Ubuntu multiarch —
	@# and wrong quietly, since a module in the wrong directory is a module PAM
	@# never loads. scripts/install-release.sh was already asking; it is the same
	@# script now, so the two install routes cannot disagree.
	PAMDIR=$$(scripts/pam-module-dir.sh) && \
		echo "  PAM module -> $$PAMDIR/$(PAM_MODULE)" && \
		sudo install -m 0644 -o root -g root $(BINARY_DIR)/$(PAM_MODULE) "$$PAMDIR/$(PAM_MODULE)"
	sudo cp $(BINARY_DIR)/$(BROKER_BINARY) /usr/local/bin/
	sudo cp $(BINARY_DIR)/$(ADMIN_BINARY) /usr/local/bin/
	sudo cp $(BINARY_DIR)/$(ENROLL_BINARY) /usr/local/bin/
	sudo cp configs/systemd/oauth2-pam-broker.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable oauth2-pam-broker

## Install development version
install-dev: build
	@echo "Installing development version..."
	PAMDIR=$$(scripts/pam-module-dir.sh) && \
		echo "  PAM module -> $$PAMDIR/$(PAM_MODULE)" && \
		sudo install -m 0644 -o root -g root $(BINARY_DIR)/$(PAM_MODULE) "$$PAMDIR/$(PAM_MODULE)"
	sudo cp $(BINARY_DIR)/$(BROKER_BINARY) /usr/local/bin/
	sudo cp $(BINARY_DIR)/$(ADMIN_BINARY) /usr/local/bin/
	sudo cp $(BINARY_DIR)/$(ENROLL_BINARY) /usr/local/bin/
	@# 0750 root-owned, like the release installer: the directory holding a config
	@# with a secret in it is not one other users should be able to list.
	sudo install -d -m 0750 -o root -g root /etc/oauth2-pam
	@# 0600 root-owned, because the example carries client_secret inline and the
	@# broker refuses to read a secret out of a file other users can read. And it
	@# is never overwritten: this target is run repeatedly during development, and
	@# clobbering an edited config with the placeholder example loses the work.
	@if [ -f /etc/oauth2-pam/broker.yaml ]; then \
		echo "  keeping existing /etc/oauth2-pam/broker.yaml"; \
	else \
		sudo install -m 0600 -o root -g root configs/example.yaml /etc/oauth2-pam/broker.yaml; \
		echo "  wrote /etc/oauth2-pam/broker.yaml from the example — edit it before starting the broker"; \
	fi
	sudo cp configs/systemd/oauth2-pam-broker.service /etc/systemd/system/
	sudo systemctl daemon-reload

## Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BINARY_DIR)
	rm -f coverage.out

## Run linter
lint:
	@echo "Running linter..."
	golangci-lint run

## Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

## Run go vet
vet:
	@echo "Running go vet..."
	go vet ./...

## Tidy dependencies
tidy:
	@echo "Tidying dependencies..."
	go mod tidy

## Generate coverage report
coverage: test
	@echo "Generating coverage report..."
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

## Run security scan
security:
	@echo "Running security scan..."
	gosec ./...

## Create release build (linux only - PAM modules are linux-specific)
##
## The three binaries cross-compile. The module does not: it is a shared object
## linked against the host's libpam and libjson-c, so this target can only produce
## a .so for the architecture it is running on. That is why release.yml builds on
## native amd64 and arm64 runners, and why a published release comes from the
## workflow rather than from here — this target produces one architecture's module
## and both architectures' binaries, and used to name the module amd64 whatever it
## ran on.
release: clean
	@echo "Creating release build..."
	@mkdir -p $(BINARY_DIR)
	GOOS=linux GOARCH=amd64 go build $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(BROKER_BINARY)-linux-amd64 ./cmd/broker
	@if [ "$$(uname -s)" = "Linux" ]; then \
		arch=$$(go env GOARCH); \
		$(CC) $(PAM_CFLAGS) $(PAM_VERSION_FLAGS) -fPIC $(PAM_LDFLAGS) \
			-o $(BINARY_DIR)/$(PAM_MODULE)-linux-$$arch $(PAM_SRC) $(PAM_LDLIBS); \
		scripts/verify-pam-symbols.sh $(BINARY_DIR)/$(PAM_MODULE)-linux-$$arch; \
		echo "release: built $(PAM_MODULE)-linux-$$arch — the other architecture needs a host of that architecture"; \
	else \
		echo "release: skipping $(PAM_MODULE) — requires a Linux C toolchain (see docker-build-pam)"; \
	fi
	GOOS=linux GOARCH=amd64 go build $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(ADMIN_BINARY)-linux-amd64 ./cmd/oauth2-pam-admin
	GOOS=linux GOARCH=amd64 go build $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(ENROLL_BINARY)-linux-amd64 ./cmd/oauth2-pam-enroll
	GOOS=linux GOARCH=arm64 go build $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(BROKER_BINARY)-linux-arm64 ./cmd/broker
	GOOS=linux GOARCH=arm64 go build $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(ADMIN_BINARY)-linux-arm64 ./cmd/oauth2-pam-admin
	GOOS=linux GOARCH=arm64 go build $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(ENROLL_BINARY)-linux-arm64 ./cmd/oauth2-pam-enroll

## Validate project structure
validate:
	@echo "Validating project structure..."
	@test -f go.mod || (echo "go.mod not found" && exit 1)
	@test -f README.md || (echo "README.md not found" && exit 1)
	@test -f LICENSE || (echo "LICENSE not found" && exit 1)
	@test -d cmd || (echo "cmd directory not found" && exit 1)
	@test -d pkg || (echo "pkg directory not found" && exit 1)
	@echo "Project structure validation passed"

## Show help
help:
	@echo "Available targets:"
	@echo "  build             Build all binaries"
	@echo "  build-broker      Build authentication broker daemon"
	@echo "  build-pam         Build PAM module (.so) — Linux only"
	@echo "  docker-build-pam  Build the PAM module in a Linux container"
	@echo "  build-admin       Build admin CLI tool"
	@echo "  build-enroll      Build enrollment CLI tool"
	@echo "  test              Run all tests"
	@echo "  test-unit         Run unit tests only"
	@echo "  test-cbridge      C unit tests for the PAM module bridge"
	@echo "  test-integration  Run the container harness (needs Docker)"
	@echo "  test-cbridge-mutations      Check the C bridge tests can still fail"
	@echo "  test-integration-mutations  Check the harness still catches the v0.1.x bypass"
	@echo "  verify-linux      Vet, test and lint under Linux, cgo included (needs Docker)"
	@echo "  install           Install binaries to system"
	@echo "  install-dev       Install development version"
	@echo "  clean             Clean build artifacts"
	@echo "  lint              Run linter"
	@echo "  fmt               Format code"
	@echo "  vet               Run go vet"
	@echo "  tidy              Tidy dependencies"
	@echo "  coverage          Generate coverage report"
	@echo "  security          Run security scan"
	@echo "  release           Create release build"
	@echo "  validate          Validate project structure"
	@echo "  help              Show this help message"
