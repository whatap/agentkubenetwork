package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/tagcount"
	"github.com/whatap/golib/lang/pack"
)

type shutdownSender struct{ closed chan struct{} }

func (*shutdownSender) Identity() (int64, int32)                       { return 1, 1 }
func (*shutdownSender) Send(context.Context, *pack.TagCountPack) error { return nil }
func (s *shutdownSender) Close() error {
	close(s.closed)
	return nil
}

type shutdownFinalWrite struct {
	data   []byte
	joined bool
}

type shutdownWriter struct {
	entered, release, joined chan struct{}
	final                    chan shutdownFinalWrite
	once                     sync.Once
	periodicErr, finalErr    error
}

func (w *shutdownWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte(`"final":true`)) {
		joined := false
		select {
		case <-w.joined:
			joined = true
		default:
		}
		w.final <- shutdownFinalWrite{append([]byte(nil), p...), joined}
		if w.finalErr != nil {
			return 0, w.finalErr
		}
		return len(p), nil
	}
	w.once.Do(func() { close(w.entered) })
	<-w.release
	if w.periodicErr != nil {
		return 0, w.periodicErr
	}
	return len(p), nil
}

func TestTagCountShutdownClosesTransportBeforeBlockedReporter(t *testing.T) {
	if err := exerciseBlockedReporterShutdown(t, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestTagCountShutdownPreservesWriterAndRunErrors(t *testing.T) {
	periodicErr := errors.New("periodic writer failed")
	finalErr := errors.New("final writer failed")
	runErr := errors.New("original run failed")
	err := exerciseBlockedReporterShutdown(t, periodicErr, finalErr, runErr)
	for _, want := range []error{periodicErr, finalErr, runErr} {
		if !errors.Is(err, want) {
			t.Errorf("shutdown lost %v: %v", want, err)
		}
	}
}

func exerciseBlockedReporterShutdown(t *testing.T, periodicErr, finalErr, runErr error) error {
	t.Helper()
	sender := &shutdownSender{closed: make(chan struct{})}
	exporter, err := tagcount.NewExporter(sender, tagcount.ExporterConfig{
		NodeName: "node", QueueCapacity: 1, DrainTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	w := &shutdownWriter{
		entered: make(chan struct{}), release: make(chan struct{}), joined: make(chan struct{}),
		final: make(chan shutdownFinalWrite, 1), periodicErr: periodicErr, finalErr: finalErr,
	}
	stop := startTagCountReporter(context.Background(), w, exporter.Snapshot, "info", time.Millisecond)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(w.release) }) }
	var finished chan struct{}
	t.Cleanup(func() {
		release()
		stop()
		exporter.Close()
		if finished != nil {
			awaitShutdownSignal(t, finished, "finalizer cleanup")
		}
	})
	awaitShutdownSignal(t, w.entered, "periodic writer entry")

	joinStarted := make(chan struct{})
	result := make(chan error, 1)
	finished = make(chan struct{})
	go func() {
		defer close(finished)
		result <- finalizeTagCount(exporter, func() error {
			close(joinStarted)
			err := stop()
			close(w.joined)
			return err
		}, w, runErr)
	}()

	// The writer remains blocked until BOTH transport cleanup and the return
	// from exporter.Close (observed at the reporter join) have occurred.
	select {
	case <-sender.closed:
	case <-time.After(time.Second):
		t.Error("transport Close blocked behind periodic diagnostics Write")
	}
	awaitShutdownSignal(t, joinStarted, "reporter join entry")
	select {
	case <-finished:
		t.Error("shutdown returned without joining the blocked reporter")
	default:
	}
	select {
	case <-w.final:
		t.Error("final diagnostics ran before releasing the periodic writer")
	default:
	}

	release()
	awaitShutdownSignal(t, finished, "shutdown completion")
	got := <-result
	select {
	case final := <-w.final:
		if !final.joined {
			t.Error("final diagnostics were written before the reporter joined")
		}
		var entry struct {
			Final     bool `json:"final"`
			RunFailed bool `json:"run_failed"`
		}
		if err := json.Unmarshal(final.data, &entry); err != nil {
			t.Fatal(err)
		}
		if !entry.Final || entry.RunFailed != (runErr != nil || periodicErr != nil) {
			t.Errorf("unexpected final status: %s", final.data)
		}
	default:
		t.Error("missing final diagnostics attempt")
	}
	return got
}

func awaitShutdownSignal(t *testing.T, ch <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}
