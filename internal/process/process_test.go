package process

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const containerID = "3f9c2e1d4b5a6978a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f6071"

func writeProc(t *testing.T, root string, pid uint32, comm string, startTime uint64, cmdline []string, cgroup string) {
	t.Helper()
	dir := filepath.Join(root, strconv.FormatUint(uint64(pid), 10))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Fields 3..52 after the parenthesised comm; field 22 (starttime) is index 19.
	fields := make([]string, 50)
	for index := range fields {
		fields[index] = "0"
	}
	fields[0] = "S"
	fields[19] = strconv.FormatUint(startTime, 10)
	stat := strconv.FormatUint(uint64(pid), 10) + " (" + comm + ") " + strings.Join(fields, " ") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
	if cmdline != nil {
		if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(strings.Join(cmdline, "\x00")+"\x00"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if cgroup != "" {
		if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(cgroup), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLookupReadsCommCmdlineStartTimeAndContainerID(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 4242, "nginx: worker", 98765, []string{"nginx", "-g", "daemon off;"},
		"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234.slice/cri-containerd-"+containerID+".scope\n")

	resolver := NewResolver(root)
	process, ok := resolver.Lookup(4242)
	if !ok {
		t.Fatal("expected lookup to succeed")
	}
	if process.PID != 4242 || process.Comm != "nginx: worker" || process.StartTimeTicks != 98765 {
		t.Fatalf("unexpected identity: %+v", process)
	}
	if process.Cmdline != "nginx -g daemon off;" {
		t.Fatalf("unexpected cmdline %q", process.Cmdline)
	}
	if process.ContainerID != containerID || process.Via != Via {
		t.Fatalf("unexpected container/via: %+v", process)
	}
}

func TestLookupReturnsFalseForZeroOrMissingPID(t *testing.T) {
	resolver := NewResolver(t.TempDir())
	if _, ok := resolver.Lookup(0); ok {
		t.Fatal("pid 0 must not resolve")
	}
	if _, ok := resolver.Lookup(77); ok {
		t.Fatal("missing /proc entry must not resolve")
	}
}

func TestLookupLeavesContainerIDEmptyForHostProcess(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 1, "systemd", 1, []string{"/sbin/init"}, "0::/init.scope\n")
	process, ok := NewResolver(root).Lookup(1)
	if !ok || process.ContainerID != "" || process.Comm != "systemd" {
		t.Fatalf("unexpected host process: %+v ok=%v", process, ok)
	}
}

func TestLookupCachesUntilTTLThenDetectsPIDReuse(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	resolver := NewResolver(root, WithTTL(10*time.Second), withClock(func() time.Time { return now }))

	writeProc(t, root, 500, "python3", 100, []string{"python3", "client.py"}, "")
	first, _ := resolver.Lookup(500)

	// Replace the process behind the PID; within TTL the cache still answers.
	writeProc(t, root, 500, "curl", 200, []string{"curl"}, "")
	cached, _ := resolver.Lookup(500)
	if cached.Comm != first.Comm || cached.StartTimeTicks != 100 {
		t.Fatalf("expected cached identity within TTL, got %+v", cached)
	}

	now = now.Add(11 * time.Second)
	fresh, ok := resolver.Lookup(500)
	if !ok || fresh.Comm != "curl" || fresh.StartTimeTicks != 200 {
		t.Fatalf("expected reused PID to resolve to new process, got %+v", fresh)
	}

	// Process exit drops the cache entry instead of serving stale identity.
	now = now.Add(11 * time.Second)
	if err := os.RemoveAll(filepath.Join(root, "500")); err != nil {
		t.Fatal(err)
	}
	if _, ok := resolver.Lookup(500); ok {
		t.Fatal("exited process must not resolve")
	}
}

func TestLookupTruncatesCmdline(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 9, "java", 5, []string{"java", strings.Repeat("x", 100)}, "")
	process, _ := NewResolver(root, WithMaxCmdline(16)).Lookup(9)
	if len(process.Cmdline) != 16 {
		t.Fatalf("expected truncated cmdline, got %d bytes", len(process.Cmdline))
	}
}

func TestParseContainerIDAcrossRuntimes(t *testing.T) {
	cases := map[string]string{
		"0::/kubepods.slice/kubepods-pod1.slice/crio-" + containerID + ".scope\n":      containerID,
		"12:pids:/kubepods/burstable/pod1/" + containerID + "\n":                       containerID,
		"3:cpu:/docker/" + containerID + "\n":                                          containerID,
		"0::/system.slice/kubelet.service\n":                                           "",
		"0::/kubepods.slice/kubepods-pod1.slice/cri-containerd-deadbeef.scope\n":       "",
		"0::/user.slice/user-1000.slice/session-1.scope\n1:name=systemd:/user.slice\n": "",
	}
	for input, expected := range cases {
		if actual := ParseContainerID(input); actual != expected {
			t.Errorf("ParseContainerID(%q) = %q, want %q", input, actual, expected)
		}
	}
}
