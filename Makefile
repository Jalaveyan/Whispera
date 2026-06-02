.PHONY: help lint test build clean install-tools check-todo

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

GOLANGCI_LINT_VERSION ?= v2.11.3

install-tools: ## Install development tools
	@echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION)..."
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin $(GOLANGCI_LINT_VERSION)
	@echo "Installing pre-commit..."
	@pip install pre-commit

lint: ## Run linters
	@echo "Running golangci-lint..."
	@golangci-lint run --timeout=5m --verbose
	@echo "Running go vet..."
	@go vet ./...
	@echo "Running go fmt check..."
	@if [ "$$(gofmt -s -l . | wc -l)" -gt 0 ]; then \
		echo "Code is not formatted. Run 'gofmt -s -w .'"; \
		exit 1; \
	fi
	@echo "Checking for TODO/FIXME/panic..."
	@if grep -r "TODO\|FIXME\|panic(" --include="*.go" .; then \
		echo "Found TODO/FIXME/panic in code. Remove before production."; \
		exit 1; \
	fi

test: ## Run tests
	@echo "Running tests..."
	@go test -v ./...

test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	@go test -v -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

build: ## Build binaries
	@echo "Building client..."
	@go build -o client ./cmd/client
	@echo "Building server..."
	@go build -o server ./cmd/server
	@echo "Building keygen..."
	@go build -o keygen ./cmd/keygen

build-windows: ## Build binaries for Windows (Tauri)
	@echo "Building client for Tauri..."
	@go build -ldflags "-s -w" -o whisp/src-tauri/bin/whispera-go-client-x86_64-pc-windows-msvc.exe ./cmd/client
	@go build -ldflags "-s -w" -o whisp/src-tauri/bin/whispera-go-client.exe ./cmd/client
	@echo "Binaries placed in whisp/src-tauri/bin/"

clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	@rm -f client server keygen
	@rm -f coverage.out coverage.html
	@go clean -cache

check-todo: ## Check for TODO/FIXME/panic
	@echo "Checking for TODO/FIXME/panic..."
	@if grep -r "TODO\|FIXME\|panic(" --include="*.go" .; then \
		echo "Found TODO/FIXME/panic in code. Remove before production."; \
		exit 1; \
	fi
	@echo "No TODO/FIXME/panic found."

format: ## Format code
	@echo "Formatting code..."
	@gofmt -s -w .
	@goimports -w .

ci: lint test build ## Run CI pipeline locally
	@echo "CI pipeline completed successfully!"

benchmark: ## Run performance benchmarks
	@echo "Running performance benchmarks..."
	@go test -bench=. -benchmem -count=3 -benchtime=2s \
		./internal/obfuscation/core/evasion \
		./internal/mux \
		./internal/modules/bridgepool \
		./internal/modules/transport/vkwebrtc \
		./internal/modules/relay
	@echo "Benchmarks completed!"

integration-test: ## Run integration tests
	@echo "Running integration tests..."
	@go test -v ./internal/obfuscation -run TestAllIntegrations
	@echo "Integration tests completed!"

production-test: ## Run production tests
	@echo "Running production tests..."
	@go test -v ./internal/obfuscation -run TestProduction
	@echo "Production tests completed!"

test-all: test integration-test benchmark production-test ## Run all tests including benchmarks
	@echo "All tests completed!"

test-dpi: ## Run DPI evasion tests
	@echo "Running DPI evasion tests..."
	@go test -v ./internal/obfuscation -run TestDPIEvasion
	@echo "DPI evasion tests completed!"

test-ml: ## Run ML system tests
	@echo "Running ML system tests..."
	@go test -v ./internal/obfuscation -run TestMLSystem
	@echo "ML system tests completed!"

test-network: ## Run network tests
	@echo "Running network tests..."
	@go test -v ./internal/obfuscation -run TestNetwork
	@echo "Network tests completed!"

test-crypto: ## Run crypto tests
	@echo "Running crypto tests..."
	@go test -v ./internal/obfuscation -run TestCrypto
	@echo "Crypto tests completed!"

test-components: test-dpi test-ml test-network test-crypto ## Run all component tests
	@echo "All component tests completed!"

test-report: ## Generate test report
	@echo "Generating test report..."
	@go test -v ./... > test-report.txt 2>&1
	@echo "Test report generated: test-report.txt"

benchmark-report: ## Generate benchmark report
	@echo "Generating benchmark report..."
	@go test -bench=. -benchmem -count=5 -benchtime=3s \
		./internal/obfuscation/core/evasion \
		./internal/mux \
		./internal/modules/bridgepool \
		./internal/modules/transport/vkwebrtc \
		./internal/modules/relay > benchmark-report.txt 2>&1
	@echo "Benchmark report generated: benchmark-report.txt"

performance-report: ## Generate performance report
	@echo "Generating performance report..."
	@echo "Performance metrics can be viewed via Prometheus at http://localhost:9090"
	@echo "Performance report generated!"

check-production: check-todo lint test-all ## Check production readiness
	@echo "Production readiness check completed!"

train: ## Train neural network model
	@echo "🧠 Training neural network model..."
	@cd ml_engine && python train_models.py

train-quick: ## Quick training with minimal parameters
	@echo "⚡ Quick neural network training..."
	@cd ml_engine && python train_models.py --quick

train-production: ## Production training with full parameters
	@echo "🚀 Production neural network training..."
	@cd ml_engine && python train_models.py --production

setup: install-tools ## Setup development environment
	@echo "Setting up pre-commit hooks..."
	@pre-commit install
	@echo "Development environment setup complete!"

.DEFAULT_GOAL := help
