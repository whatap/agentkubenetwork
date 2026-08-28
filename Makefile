GO ?= $(shell command -v go 2>/dev/null || printf /usr/local/go/bin/go)
CLANG ?= clang

.PHONY: test vet bpf-syntax generate-ebpf build check clean

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

bpf-syntax:
	$(CLANG) -target bpf -O2 -g -Wall -Werror -fsyntax-only internal/collector/bpf/flow.bpf.c

generate-ebpf:
	./scripts/generate-ebpf-linux.sh

build:
	mkdir -p bin
	$(GO) build -trimpath -o bin/agentkubenetwork ./cmd/agentkubenetwork

check: bpf-syntax test vet build

clean:
	rm -rf bin agentkubenetwork
