GO ?= $(shell command -v go 2>/dev/null || printf /usr/local/go/bin/go)
CLANG ?= clang
BIN_DIR ?= bin
DIST_DIR ?= dist

.PHONY: test vet bpf-syntax generate-ebpf build image-binaries check clean

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

bpf-syntax:
	$(CLANG) -target bpf -O2 -g -Wall -Werror -fsyntax-only internal/collector/bpf/flow.bpf.c

generate-ebpf:
	./scripts/generate-ebpf-linux.sh

build:
	mkdir -p "$(BIN_DIR)"
	$(GO) build -trimpath -o "$(BIN_DIR)/agentkubenetwork" ./cmd/agentkubenetwork
	$(GO) build -trimpath -o "$(BIN_DIR)/network-edge-submit" ./cmd/network-edge-submit

check: bpf-syntax test vet build

# Cross-compile outside Docker so shared image builders need no Go/module cache.
image-binaries:
	@set -eu; for arch in amd64 arm64; do \
		mkdir -p "$(DIST_DIR)/linux/$$arch"; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $(GO) build -trimpath -buildvcs=false -ldflags='-s -w' \
			-o "$(DIST_DIR)/linux/$$arch/agentkubenetwork" ./cmd/agentkubenetwork; \
	done

clean:
	rm -rf bin agentkubenetwork
