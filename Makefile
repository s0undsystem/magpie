BINARY := magpie
MODULE := github.com/s0undsystem/magpie
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X '$(MODULE)/internal/version.Version=$(VERSION)'

.PHONY: build test lint run clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/magpie

test:
	go vet ./...
	go test -race -cover ./...

lint:
	go vet ./...
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "staticcheck not installed; run: go install honnef.co/go/tools/cmd/staticcheck@latest"; \
		exit 1; \
	fi

run: build
	./bin/$(BINARY) $(ARGS)

clean:
	rm -rf bin/ dist/
