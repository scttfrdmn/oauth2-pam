.PHONY: build test install clean lint fmt vet tidy help

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

## Build PAM module
build-pam:
	@echo "Building PAM module..."
	@mkdir -p $(BINARY_DIR)
	CGO_ENABLED=1 go build -buildmode=c-shared $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(PAM_MODULE) ./cmd/pam-module

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

## Run integration tests
test-integration:
	@echo "Running integration tests..."
	go test $(GO_TEST_FLAGS) ./test/integration/...

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
	sudo cp configs/example.yaml /etc/oauth2-pam/broker.yaml
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
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -buildmode=c-shared $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(PAM_MODULE)-linux-amd64 ./cmd/pam-module
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
	@echo "  build-pam         Build PAM module (.so)"
	@echo "  build-admin       Build admin CLI tool"
	@echo "  test              Run all tests"
	@echo "  test-unit         Run unit tests only"
	@echo "  test-integration  Run integration tests"
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
