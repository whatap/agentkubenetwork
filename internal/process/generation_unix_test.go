//go:build linux || darwin

package process

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
)

// A FIFO pauses a real procfs fixture read after stat but before cgroup.
// No scheduling assumption or production test hook is needed.
func TestLookupRejectsGenerationChangeWhileReadingMetadata(t *testing.T) {
	for _, change := range []string{"reuse", "exit", "unreadable"} {
		t.Run(change, func(t *testing.T) {
			root := t.TempDir()
			writeProc(t, root, 500, "process-a", 100, nil, "0::/docker/"+containerID)
			fifo := filepath.Join(root, "500", "cmdline")
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Fatal(err)
			}
			resolver := NewResolver(root)
			type result struct {
				process flow.Process
				ok      bool
			}
			finished := make(chan result, 1)
			go func() { p, ok := resolver.Lookup(500); finished <- result{p, ok} }()

			deadline := time.Now().Add(3 * time.Second)
			var writer *os.File
			for {
				var err error
				writer, err = os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0)
				if err == nil {
					break
				}
				if !os.IsNotExist(err) && !os.IsTimeout(err) && !strings.Contains(err.Error(), syscall.ENXIO.Error()) {
					t.Fatal(err)
				}
				if time.Now().After(deadline) {
					t.Fatal("lookup did not reach metadata read")
				}
				time.Sleep(time.Millisecond)
			}
			defer writer.Close()
			switch change {
			case "reuse":
				writeProc(t, root, 500, "process-b", 200, nil, "0::/docker/"+strings.Repeat("b", 64))
			case "exit":
				if err := os.RemoveAll(filepath.Join(root, "500")); err != nil {
					t.Fatal(err)
				}
			case "unreadable":
				if err := os.WriteFile(filepath.Join(root, "500", "stat"), []byte("bad stat"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := writer.Write([]byte("process-b\x00")); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-finished:
				if got.ok {
					t.Fatalf("mixed/unverified process generation published: %+v", got.process)
				}
				if _, ok := resolver.cache[500]; ok {
					t.Fatal("mixed generation cached")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("metadata lookup did not finish")
			}
		})
	}
}
