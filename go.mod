module github.com/whatap/agentkubenetwork

go 1.25.0

toolchain go1.25.7

require (
	github.com/cilium/ebpf v0.22.0
	golang.org/x/net v0.58.0
)

require golang.org/x/sys v0.47.0 // indirect

tool github.com/cilium/ebpf/cmd/bpf2go
