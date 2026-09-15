//go:build linux

package conntrack

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestReceiveNetlinkDumpTimeoutDiscardsPartialSnapshot(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	if err := unix.Sendto(fds[1], conntrackMessage(dnatEntryBytes()), 0, nil); err != nil {
		t.Fatal(err)
	}
	// Rescue the old unbounded receiver so RED is an assertion, not a hung test.
	// Continued traffic must not reset the total one-second dump deadline.
	sent := make(chan error, 1)
	go func() {
		for i := 0; i < 6; i++ {
			time.Sleep(200 * time.Millisecond)
			if err := unix.Sendto(fds[1], conntrackMessage(dnatEntryBytes()), 0, nil); err != nil {
				sent <- err
				return
			}
		}
		sent <- unix.Sendto(fds[1], netlinkMessage(nlmsgDone, nil), 0, nil)
	}()
	started := time.Now()
	entries, err := receiveNetlinkDump(fds[0])
	elapsed := time.Since(started)
	if sendErr := <-sent; sendErr != nil {
		t.Fatal(sendErr)
	}
	if err == nil || len(entries) != 0 {
		t.Errorf("expired dump published partial entries: count=%d err=%v", len(entries), err)
	}
	if elapsed > 1150*time.Millisecond {
		t.Errorf("dump exceeded absolute timeout: %s", elapsed)
	}
}

func TestReceiveNetlinkDumpRejectsLateFailure(t *testing.T) {
	for _, kind := range []string{"done_errno", "done_interrupted", "entry_interrupted"} {
		t.Run(kind, func(t *testing.T) {
			fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fds[0])
			defer unix.Close(fds[1])
			for _, data := range [][]byte{conntrackMessage(dnatEntryBytes()), incompleteDumpFixture(kind)} {
				if err := unix.Sendto(fds[1], data, 0, nil); err != nil {
					t.Fatal(err)
				}
			}
			entries, err := receiveNetlinkDump(fds[0])
			if err == nil || len(entries) != 0 {
				t.Fatalf("late failure published earlier datagram: %+v err=%v", entries, err)
			}
		})
	}
}
