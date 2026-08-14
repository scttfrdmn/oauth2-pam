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

# Default target
all: build

## Build all binaries
build: build-broker build-pam build-admin build-enroll

## Build authentication broker daemon
build-broker:
	@echo "Building authentication broker..."
	@mkdir -p $(BINARY_DIR)
	go build $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(BROKER_BINARY) ./cmd/broker

## Build PAM module (Linux only — needs Linux-PAM headers and json-c)
build-pam:
	@if [ "$$(go env GOOS)" != "linux" ]; then \
		echo "build-pam: skipped — the PAM module requires Linux (Linux-PAM headers"; \
		echo "  and json-c). Build it in a Linux container:"; \
		echo "    make docker-build-pam"; \
		exit 1; \
	fi
	@echo "Building PAM module..."
	@mkdir -p $(BINARY_DIR)
	CGO_ENABLED=1 go build -buildmode=c-shared $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(PAM_MODULE) ./cmd/pam-module
	@echo "Verifying PAM entry points are present..."
	@# Per symbol, and a build host without nm fails here rather than passing
	@# quietly. The same script runs in release.yml and in the installer, so a
	@# module that gets past one of them gets past all three for the same reason.
	@scripts/verify-pam-symbols.sh $(BINARY_DIR)/$(PAM_MODULE)

## Build the PAM module in a Linux container (works from macOS)
docker-build-pam:
	@echo "Building PAM module in a Linux container..."
	@mkdir -p $(BINARY_DIR)
	docker run --rm -v "$(PWD)":/src -w /src golang:1.25 sh -c '\
		apt-get update -qq && \
		apt-get install -y -qq libpam0g-dev libjson-c-dev >/dev/null && \
		make build-pam'

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
## tests would notice if it stopped. This reintroduces each of the six fixed
## bridge defects in a copy of the source under $$TMPDIR and asserts the suite
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
## On macOS the module cannot be compiled at all, so `go build ./...`,
## `go test ./...` and golangci-lint all silently exclude cmd/pam-module — the
## most security-sensitive package here. This is the same sweep CI runs, with the
## headers present. Answers "does the Linux build compile and pass"; use
## test-integration to answer "does a login work".
verify-linux:
	@echo "Building the verification image..."
	@docker build -q -f test/docker/Dockerfile.verify -t oauth2-pam-verify . >/dev/null
	@echo "Running vet, tests and lint under Linux..."
	docker run --rm \
		-v "$(PWD)":/src \
		-v oauth2-pam-verify-gocache:/root/.cache/go-build \
		-v oauth2-pam-verify-gomod:/go/pkg/mod \
		oauth2-pam-verify \
		sh -c 'go build ./... && go vet ./... && go test -race ./... && golangci-lint run ./...'

## Install binaries to system locations
install: build
	@echo "Installing binaries..."
	sudo cp $(BINARY_DIR)/$(PAM_MODULE) /lib/security/
	sudo cp $(BINARY_DIR)/$(BROKER_BINARY) /usr/local/bin/
	sudo cp $(BINARY_DIR)/$(ADMIN_BINARY) /usr/local/bin/
	sudo cp $(BINARY_DIR)/$(ENROLL_BINARY) /usr/local/bin/
	sudo cp configs/systemd/oauth2-pam-broker.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable oauth2-pam-broker

## Install development version
install-dev: build
	@echo "Installing development version..."
	sudo cp $(BINARY_DIR)/$(PAM_MODULE) /lib/security/
	sudo cp $(BINARY_DIR)/$(BROKER_BINARY) /usr/local/bin/
	sudo cp $(BINARY_DIR)/$(ADMIN_BINARY) /usr/local/bin/
	sudo cp $(BINARY_DIR)/$(ENROLL_BINARY) /usr/local/bin/
	sudo mkdir -p /etc/oauth2-pam
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
release: clean
	@echo "Creating release build..."
	@mkdir -p $(BINARY_DIR)
	GOOS=linux GOARCH=amd64 go build $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(BROKER_BINARY)-linux-amd64 ./cmd/broker
	@# The PAM module needs cgo against Linux-PAM, so it cannot be
	@# cross-compiled from macOS; build it on Linux (or via docker-build-pam).
	@if [ "$$(go env GOOS)" = "linux" ]; then \
		GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -buildmode=c-shared $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(PAM_MODULE)-linux-amd64 ./cmd/pam-module; \
	else \
		echo "release: skipping $(PAM_MODULE) — requires a Linux build host (see docker-build-pam)"; \
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
