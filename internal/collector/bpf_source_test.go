package collector

import (
	"os"
	"strings"
	"testing"
)

func TestBPFIOExitFallsBackToUserspaceTupleResolution(t *testing.T) {
	source, err := os.ReadFile("bpf/flow.bpf.c")
	if err != nil {
		t.Fatalf("read BPF source: %v", err)
	}
	text := string(source)
	start := strings.Index(text, "static __always_inline int finish_io")
	end := strings.Index(text[start:], "static __always_inline void remember_socket_context")
	if start < 0 || end < 0 {
		t.Fatal("finish_io function not found")
	}
	finishIO := text[start : start+end]

	for _, required := range []string{
		"const struct socket_tuple *tuple = 0;",
		"tuple = &copy.tuple;",
		"EVENT_SOURCE_KERNEL_PLAINTEXT, 0, tuple",
	} {
		if !strings.Contains(finishIO, required) {
			t.Fatalf("finish_io missing tuple fallback contract %q", required)
		}
	}
	if strings.Contains(finishIO, "copy.tuple.family != AF_INET && copy.tuple.family != AF_INET6)\n		return 0") {
		t.Fatal("finish_io silently discards classified payload when the fentry tuple bridge is unavailable")
	}
}

func TestBPFSyscallTracepointsUseTheTraceFSWireLayout(t *testing.T) {
	source, err := os.ReadFile("bpf/flow.bpf.c")
	if err != nil {
		t.Fatalf("read BPF source: %v", err)
	}
	text := string(source)
	for _, required := range []string{
		"struct trace_event_raw_sys_enter {",
		"__u64 tracepoint_header[2];",
		"unsigned long args[6];",
		"struct trace_event_raw_sys_exit {",
		"long ret;",
		"bpf_probe_read_kernel(&fd, sizeof(fd), &ctx->args[0])",
		"bpf_probe_read_kernel(&result, sizeof(result), &ctx->ret)",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("BPF source missing fixed syscall tracepoint contract %q", required)
		}
	}
	for _, forbidden := range []string{
		"struct trace_event_raw_sys_enter {\n	struct trace_entry common;",
		"struct trace_event_raw_sys_exit {\n	struct trace_entry common;",
		"bpf_core_read(&fd, sizeof(fd), &ctx->args[0])",
		"bpf_core_read(&result, sizeof(result), &ctx->ret)",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("BPF source still trusts incompatible syscall BTF layout %q", forbidden)
		}
	}
}
