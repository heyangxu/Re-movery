.PHONY: build test clean lint run

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
BINARY_NAME=movery
BINARY_UNIX=$(BINARY_NAME)_unix

# Build parameters
BUILD_DIR=go/bin
MAIN_PATH=./go/cmd/movery

all: test build

build:
	cd go && $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) -v $(MAIN_PATH)

test:
	cd go && $(GOTEST) -v ./...

clean:
	cd go && $(GOCLEAN)
	rm -f $(BUILD_DIR)/*

run:
	cd go && $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) -v $(MAIN_PATH)
	./$(BUILD_DIR)/$(BINARY_NAME)

lint:
	cd go && golangci-lint run

deps:
	cd go && $(GOMOD) download

# Cross compilation
build-linux:
	cd go && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_UNIX) -v $(MAIN_PATH)

build-windows:
	cd go && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME).exe -v $(MAIN_PATH)

# Help target
help:
	@echo "Available targets:"
	@echo "  build        - Build the project"
	@echo "  test         - Run tests"
	@echo "  clean        - Clean build files"
	@echo "  run          - Build and run the project"
	@echo "  lint         - Run linter"
	@echo "  deps         - Download dependencies"
	@echo "  build-linux  - Build for Linux"
	@echo "  build-windows- Build for Windows" 