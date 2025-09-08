# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
BINARY_NAME=account-manage
BINARY_UNIX=$(BINARY_NAME)_unix

# Build the application
.PHONY: build
build:
	$(GOBUILD) -o $(BINARY_NAME) -v ./cmd/server

# Build for Linux
.PHONY: build-linux
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_UNIX) -v ./cmd/server

# Clean build artifacts
.PHONY: clean
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_UNIX)

# Run tests
.PHONY: test
test:
	$(GOTEST) -v ./...

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out

# Download dependencies
.PHONY: deps
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Run the application
.PHONY: run
run:
	$(GOBUILD) -o $(BINARY_NAME) -v ./cmd/server
	./$(BINARY_NAME)

# Run with hot reload (requires air)
.PHONY: dev
dev:
	air

# Format code
.PHONY: fmt
fmt:
	$(GOCMD) fmt ./...

# Lint code
.PHONY: lint
lint:
	golangci-lint run

# Generate mocks
.PHONY: mocks
mocks:
	mockgen -source=internal/domain/repositories/user_repository.go -destination=tests/mocks/user_repository_mock.go
	mockgen -source=internal/domain/repositories/chain_account_repository.go -destination=tests/mocks/chain_account_repository_mock.go

# Database migration
.PHONY: migrate
migrate:
	$(GOCMD) run ./cmd/server migrate

# Docker build
.PHONY: docker-build
docker-build:
	docker build -t $(BINARY_NAME) .

# Docker run
.PHONY: docker-run
docker-run:
	docker run -p 8080:8080 $(BINARY_NAME)

# Help
.PHONY: help
help:
	@echo "Available commands:"
	@echo "  build         - Build the application"
	@echo "  build-linux   - Build for Linux"
	@echo "  clean         - Clean build artifacts"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  deps          - Download dependencies"
	@echo "  run           - Run the application"
	@echo "  dev           - Run with hot reload"
	@echo "  fmt           - Format code"
	@echo "  lint          - Lint code"
	@echo "  mocks         - Generate mocks"
	@echo "  migrate       - Run database migration"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-run    - Run Docker container"
	@echo "  help          - Show this help"
