package collector

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// This executes the actual C helper bodies with host-only BPF/CO-RE shims.
// It does not load BPF, validate relocations, or claim Linux verifier coverage.
func TestBPFProductionHelperSafety(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("host BPF regressions require python3")
	}
	clang := os.Getenv("CLANG")
	if clang == "" {
		clang = "clang"
	}
	if _, err := exec.LookPath(clang); err != nil {
		t.Skip("host BPF regressions require clang and its sanitizer runtime")
	}
	for _, name := range []string{"scatter", "identity", "destination"} {
		t.Run(name, func(t *testing.T) {
			output, err := exec.Command(python, "testdata/bpf_safety/run.py", "--case", name).CombinedOutput()
			if err != nil {
				t.Fatalf("production BPF helper regression: %v\n%s", err, output)
			}
			t.Log(string(output))
		})
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
