# Viracochan Makefile
# Provides common development tasks for building, testing, and maintaining the project

# Color codes for output
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NOCOLOR := \033[0m

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOMOD := $(GOCMD) mod
GOPATH := $(shell go env GOPATH)

# Project parameters
PROJECT_NAME := viracochan
MAIN_PACKAGE := github.com/source-c/$(PROJECT_NAME)
DEMO_DIR := ./cmd
BUILD_DIR := ./build
BIN_DIR := ./bin

# Demo applications
DEMOS := demo-distributed demo-disaster-recovery demo-migration \
         demo-audit-trail demo-concurrent demo-encryption demo-simple

# Default target
.PHONY: all
all: fmt lint test build

# Help target
.PHONY: help
help:
	@echo "$(GREEN)Viracochan Makefile$(NOCOLOR)"
	@echo ""
	@echo "Available targets:"
	@echo "  $(YELLOW)all$(NOCOLOR)        - Run fmt, lint, test, and build"
	@echo "  $(YELLOW)test$(NOCOLOR)       - Run all tests"
	@echo "  $(YELLOW)test-race$(NOCOLOR)  - Run tests with race detector"
	@echo "  $(YELLOW)test-cover$(NOCOLOR) - Run tests with coverage report"
	@echo "  $(YELLOW)vuln$(NOCOLOR)       - Check for known vulnerabilities"
	@echo "  $(YELLOW)fmt$(NOCOLOR)        - Format code with gci and gofumpt"
	@echo "  $(YELLOW)lint$(NOCOLOR)       - Run golangci-lint"
	@echo "  $(YELLOW)demos$(NOCOLOR)      - Build all demo applications"
	@echo "  $(YELLOW)run-demos$(NOCOLOR)  - Run all demos with sample data"
	@echo "  $(YELLOW)build$(NOCOLOR)      - Build the library"
	@echo "  $(YELLOW)clean$(NOCOLOR)      - Clean build artifacts and demo data"
	@echo "  $(YELLOW)clean-all$(NOCOLOR)  - Clean everything including dependencies"
	@echo "  $(YELLOW)deps$(NOCOLOR)       - Download and verify dependencies"
	@echo "  $(YELLOW)verify$(NOCOLOR)     - Verify module dependencies"

# Testing targets
.PHONY: test
test:
	@echo "$(GREEN)# Running tests...$(NOCOLOR)"
	$(GOTEST) -v ./...

.PHONY: test-race
test-race:
	@echo "$(GREEN)# Running tests with race detector...$(NOCOLOR)"
	$(GOTEST) -race -v ./...

.PHONY: test-cover
test-cover:
	@echo "$(GREEN)# Running tests with coverage...$(NOCOLOR)"
	$(GOTEST) -v -coverprofile=coverage.out ./...
	@echo "$(GREEN)# Generating coverage report...$(NOCOLOR)"
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)# Coverage report generated: coverage.html$(NOCOLOR)"

# Vulnerability checking
.build-govulncheck:
	@if [ ! -f $(GOPATH)/bin/govulncheck ]; then \
		echo "$(GREEN)# Installing govulncheck...$(NOCOLOR)"; \
		go install golang.org/x/vuln/cmd/govulncheck@latest; \
	fi

.PHONY: vuln
vuln: .build-govulncheck
	@echo "$(GREEN)# Checking for vulnerabilities...$(NOCOLOR)"
	govulncheck ./...

# Code formatting
.build-fmt-tools:
	@if [ ! -f $(GOPATH)/bin/gci ]; then \
		echo "$(GREEN)# Installing gci...$(NOCOLOR)"; \
		go install github.com/daixiang0/gci@latest; \
	fi
	@if [ ! -f $(GOPATH)/bin/gofumpt ]; then \
		echo "$(GREEN)# Installing gofumpt...$(NOCOLOR)"; \
		go install mvdan.cc/gofumpt@latest; \
	fi

.PHONY: fmt
fmt: .build-fmt-tools
	@echo "$(GREEN)# Running gci fmt$(NOCOLOR)"
	gci write --skip-generated -s standard -s default -s 'prefix(github.com/source-c)' -s alias --custom-order .
	@echo "$(GREEN)# Running gofumpt$(NOCOLOR)"
	gofumpt -w -l .

# Linting
.build-golangci-lint:
	@if [ ! -f $(BIN_DIR)/golangci-lint ]; then \
		echo "$(GREEN)# Installing golangci-lint binary...$(NOCOLOR)"; \
		mkdir -p $(BIN_DIR); \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(BIN_DIR); \
	fi

.PHONY: lint
lint: .build-golangci-lint
	@echo "$(GREEN)# Running configured linters...$(NOCOLOR)"
	$(BIN_DIR)/golangci-lint run --config=.golangci.yml ./...

# Quick lint without config file (fallback)
.PHONY: lint-quick
lint-quick: .build-golangci-lint
	@echo "$(GREEN)# Running quick lint check...$(NOCOLOR)"
	$(BIN_DIR)/golangci-lint run ./...

# Demo applications
.PHONY: demos
demos:
	@echo "$(GREEN)# Building demo applications...$(NOCOLOR)"
	@mkdir -p $(BUILD_DIR)
	@for demo in $(DEMOS); do \
		echo "$(YELLOW)  Building $$demo...$(NOCOLOR)"; \
		$(GOBUILD) -o $(BUILD_DIR)/$$demo $(DEMO_DIR)/$$demo/*.go || exit 1; \
	done
	@echo "$(GREEN)# All demos built successfully in $(BUILD_DIR)/$(NOCOLOR)"

# Run individual demos
.PHONY: run-demo-%
run-demo-%:
	@echo "$(GREEN)# Running demo: $*$(NOCOLOR)"
	@if [ -f $(DEMO_DIR)/$*/main.go ]; then \
		$(GOCMD) run $(DEMO_DIR)/$*/*.go; \
	else \
		echo "$(RED)Demo $* not found$(NOCOLOR)"; \
		exit 1; \
	fi

# Run all demos with sample configurations
.PHONY: run-demos
run-demos:
	@echo "$(GREEN)# Running all demo applications...$(NOCOLOR)"
	@echo "$(YELLOW)Note: This will create temporary directories for demo data$(NOCOLOR)"
	@echo ""
	@for demo in $(DEMOS); do \
		echo "$(GREEN)====================================="; \
		echo "# Running $$demo"; \
		echo "=====================================$(NOCOLOR)"; \
		if [ "$$demo" = "demo-concurrent" ]; then \
			$(GOCMD) run $(DEMO_DIR)/$$demo/*.go -duration 5s -workers 3 || true; \
		elif [ "$$demo" = "demo-distributed" ]; then \
			$(GOCMD) run $(DEMO_DIR)/$$demo/*.go -nodes 2 || true; \
		else \
			$(GOCMD) run $(DEMO_DIR)/$$demo/*.go || true; \
		fi; \
		echo ""; \
		sleep 2; \
	done
	@echo "$(GREEN)# All demos completed$(NOCOLOR)"

# Build targets
.PHONY: build
build:
	@echo "$(GREEN)# Building library...$(NOCOLOR)"
	$(GOBUILD) -v ./...

.PHONY: build-all
build-all: build demos
	@echo "$(GREEN)# All builds completed$(NOCOLOR)"

# Dependency management
.PHONY: deps
deps:
	@echo "$(GREEN)# Downloading dependencies...$(NOCOLOR)"
	$(GOMOD) download
	$(GOMOD) tidy

.PHONY: verify
verify:
	@echo "$(GREEN)# Verifying dependencies...$(NOCOLOR)"
	$(GOMOD) verify

# Clean targets
.PHONY: clean
clean:
	@echo "$(GREEN)# Cleaning build artifacts and demo data...$(NOCOLOR)"
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.out coverage.html
	@rm -rf distributed-demo disaster-recovery-demo migration-* audit-demo concurrent-demo encryption-demo
	@rm -rf config-data app-settings-export.json
	@rm -rf /tmp/viracochan-test
	@echo "$(GREEN)# Clean completed$(NOCOLOR)"

.PHONY: clean-all
clean-all: clean
	@echo "$(GREEN)# Cleaning everything including tools...$(NOCOLOR)"
	@rm -rf $(BIN_DIR)
	@rm -rf vendor/
	@$(GOCMD) clean -modcache
	@echo "$(GREEN)# Deep clean completed$(NOCOLOR)"

# Development workflow targets
.PHONY: dev
dev: fmt lint test
	@echo "$(GREEN)# Development checks passed$(NOCOLOR)"

.PHONY: ci
ci: deps fmt lint test vuln
	@echo "$(GREEN)# CI checks passed$(NOCOLOR)"

# Pre-commit hook
.PHONY: pre-commit
pre-commit: fmt lint test
	@echo "$(GREEN)# Pre-commit checks passed$(NOCOLOR)"

# Installation target
.PHONY: install
install:
	@echo "$(GREEN)# Installing viracochan library...$(NOCOLOR)"
	$(GOCMD) install -v ./...

# Documentation
.PHONY: docs
docs:
	@echo "$(GREEN)# Generating documentation...$(NOCOLOR)"
	@echo "$(YELLOW)Opening godoc server on http://localhost:6060$(NOCOLOR)"
	@godoc -http=:6060

# Benchmarks
.PHONY: bench
bench:
	@echo "$(GREEN)# Running benchmarks...$(NOCOLOR)"
	$(GOTEST) -bench=. -benchmem ./...

# Check for common issues
.PHONY: check
check: fmt lint test vuln
	@echo "$(GREEN)# All checks passed$(NOCOLOR)"

# Version information
.PHONY: version
version:
	@echo "$(GREEN)Viracochan Development Tools$(NOCOLOR)"
	@echo "Go version: $$(go version)"
	@echo "Module: $(MAIN_PACKAGE)"
	@if [ -f $(BIN_DIR)/golangci-lint ]; then \
		echo "golangci-lint: $$($(BIN_DIR)/golangci-lint version)"; \
	fi

.DEFAULT_GOAL := help
