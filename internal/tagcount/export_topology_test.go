package tagcount

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/whatap/agentkubenetwork/internal/topology"
	"github.com/whatap/golib/lang/pack"
)

func exportTopologyForTest(t *testing.T, e *Exporter, s topology.Summary) error {
	t.Helper()
	typed, ok := any(e).(interface{ ExportTopology(topology.Summary) error })
	if !ok {
		t.Fatal("TagCount exporter has no topology export path")
	}
	return typed.ExportTopology(s)
}

func TestExportTopologyDrainsIndependentSnapshotsThroughSharedQueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var sent []*pack.TagCountPack
		sender := &exporterTestSender{closed: make(chan struct{}), send: func(ctx context.Context, p *pack.TagCountPack) error {
			select {
			case <-release:
				sent = append(sent, p)
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}}
		e, err := NewExporter(sender, ExporterConfig{NodeName: "node", QueueCapacity: 3, DrainTimeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer e.Close()
		if err := e.Export(exporterTestWindow()); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		s := topologyTestSummary()
		before := s
		for i := 0; i < 2; i++ {
			if err := exportTopologyForTest(t, e, s); err != nil {
				t.Fatal(err)
			}
		}
		s.Source.UID, s.Destination.Name, s.ClusterID, s.LastSeenMS = "mutated-uid", "mutated-name", "mutated-cluster", 1
		close(release)
		if err := e.Close(); err != nil {
			t.Fatal(err)
		}
		if len(sent) != 3 || sent[0].Category != Category {
			t.Fatalf("shared queue did not drain L4 and topology: %v", sent)
		}
		for _, p := range sent[1:] {
			assertTopologyPack(t, p, before)
			if p.Pcode != 123 || p.Oid != 456 {
				t.Fatal("topology did not use exporter identity")
			}
		}
		if sent[1] == sent[2] || sent[1].Tags == sent[2].Tags || sent[1].Data == sent[2].Data {
			t.Fatal("queued summaries share mutable packs")
		}
		if !bytes.Equal(pack.ToBytesPack(sent[1]), pack.ToBytesPack(sent[2])) {
			t.Fatal("repeat topology evidence acquired a per-record identity")
		}
		got := e.Snapshot()
		if got.Queued != 3 || got.Written != 3 || got.Failed != 0 || got.Pending != 0 || got.Dropped != 0 {
			t.Fatalf("incorrect shared queue accounting: %+v", got)
		}
		if err := e.Close(); err != nil {
			t.Fatalf("Close is not idempotent: %v", err)
		}
		for _, input := range []topology.Summary{before, {}} {
			if err := exportTopologyForTest(t, e, input); !errors.Is(err, ErrClosed) {
				t.Fatalf("closed state must precede validation: %v", err)
			}
		}
		select {
		case <-sender.closed:
		default:
			t.Fatal("sender was not closed after drain")
		}
	})
}

func TestExportTopologyRejectsMalformedWithoutEnqueue(t *testing.T) {
	sender := &exporterTestSender{closed: make(chan struct{}), send: func(context.Context, *pack.TagCountPack) error {
		t.Error("invalid topology reached sender")
		return nil
	}}
	e, err := NewExporter(sender, ExporterConfig{NodeName: "node", QueueCapacity: 1, DrainTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	before := e.Snapshot()
	s := topologyTestSummary()
	s.ClusterID = ""
	for _, input := range []topology.Summary{s, {}} {
		if err := exportTopologyForTest(t, e, input); err == nil {
			t.Fatal("invalid topology was accepted")
		}
	}
	if got := e.Snapshot(); got != before || e.Err() != nil {
		t.Fatalf("invalid input changed queue accounting or terminal state: %+v", got)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
}

// A full queue must not thin a summary window: the exporter refuses the summary
// and counts no loss, so the caller can offer it again.
func TestExportTopologyFullQueueRefusesWithoutCountingLoss(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		sender := &exporterTestSender{closed: make(chan struct{}), send: func(ctx context.Context, _ *pack.TagCountPack) error {
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}}
		e, err := NewExporter(sender, ExporterConfig{NodeName: "node", QueueCapacity: 1, DrainTimeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer e.Close()
		// The sender holds the first summary; the second fills the queue.
		for i := 0; i < 2; i++ {
			if err := exportTopologyForTest(t, e, topologyTestSummary()); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
		}
		for i := 0; i < 2; i++ {
			if err := exportTopologyForTest(t, e, topologyTestSummary()); !errors.Is(err, topology.ErrNotQueued) {
				t.Fatalf("a full queue must refuse the summary: %v", err)
			}
		}
		got := e.Snapshot()
		if got.Queued != 2 || got.Dropped != 0 || got.Pending != 2 || got.Written != 0 || e.Dropped() != 0 || e.Err() != nil {
			t.Fatalf("a refused summary was counted or became terminal: %+v", got)
		}
		close(release)
		synctest.Wait()
		if err := exportTopologyForTest(t, e, topologyTestSummary()); err != nil {
			t.Fatalf("the summary was refused after the queue drained: %v", err)
		}
		if err := e.Close(); err != nil {
			t.Fatalf("refusals were reported as queue loss: %v", err)
		}
		if got := e.Snapshot(); got.Queued != 3 || got.Written != 3 || got.Pending != 0 || got.Failed != 0 || got.Dropped != 0 {
			t.Fatalf("incorrect topology drain accounting: %+v", got)
		}
	})
}

func TestExportTopologyFailureIsTerminalWithoutRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		calls := 0
		sender := &exporterTestSender{closed: make(chan struct{}), send: func(ctx context.Context, _ *pack.TagCountPack) error {
			calls++
			select {
			case <-release:
				return io.ErrUnexpectedEOF
			case <-ctx.Done():
				return ctx.Err()
			}
		}}
		e, err := NewExporter(sender, ExporterConfig{NodeName: "node", QueueCapacity: 3, DrainTimeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer e.Close()
		for i := 0; i < 3; i++ {
			if err := exportTopologyForTest(t, e, topologyTestSummary()); err != nil {
				t.Fatal(err)
			}
		}
		close(release)
		<-e.Failed()
		if !errors.Is(e.Err(), io.ErrUnexpectedEOF) {
			t.Fatal("sender failure was not propagated")
		}
		before := e.Snapshot()
		for _, input := range []topology.Summary{topologyTestSummary(), {}} {
			if err := exportTopologyForTest(t, e, input); !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("terminal failure must precede validation: %v", err)
			}
		}
		if got := e.Snapshot(); got != before {
			t.Fatal("terminal exporter enqueued additional topology")
		}
		if err := e.Close(); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("Close hid sender failure: %v", err)
		}
		if got := e.Snapshot(); calls != 1 || got.Queued != 3 || got.Failed != 1 || got.Pending != 2 || got.Written != 0 || got.Dropped != 0 {
			t.Fatalf("topology was retried or miscounted: calls=%d summary=%+v", calls, got)
		}
	})
}

func TestExportTopologyDrainDeadlineCancelsSender(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sender := &exporterTestSender{closed: make(chan struct{}), send: func(ctx context.Context, _ *pack.TagCountPack) error {
			<-ctx.Done()
			return ctx.Err()
		}}
		e, err := NewExporter(sender, ExporterConfig{NodeName: "node", QueueCapacity: 1, DrainTimeout: 100 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		defer e.Close()
		if err := exportTopologyForTest(t, e, topologyTestSummary()); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		started := time.Now()
		if err := e.Close(); !errors.Is(err, ErrDrainTimeout) {
			t.Fatalf("Close hid delivery uncertainty: %v", err)
		}
		if time.Since(started) != 100*time.Millisecond {
			t.Fatalf("unbounded topology drain: %v", time.Since(started))
		}
		synctest.Wait()
		select {
		case <-sender.closed:
		default:
			t.Fatal("timed-out sender was not closed")
		}
		select {
		case <-e.done:
		default:
			t.Fatal("topology export worker survived cancellation")
		}
	})
}

func TestExportTopologyConcurrentClose(t *testing.T) {
	sender := &exporterTestSender{closed: make(chan struct{}), send: func(context.Context, *pack.TagCountPack) error { return nil }}
	e, err := NewExporter(sender, ExporterConfig{NodeName: "node", QueueCapacity: 256, DrainTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	// Check the interface in the test goroutine before launching workers.
	if err := exportTopologyForTest(t, e, topologyTestSummary()); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Go(func() {
			for j := 0; j < 20; j++ {
				if err := exportTopologyForTest(t, e, topologyTestSummary()); err != nil && !errors.Is(err, ErrClosed) {
					t.Errorf("ExportTopology: %v", err)
				}
			}
		})
	}
	for i := 0; i < 2; i++ {
		group.Go(func() {
			if err := e.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		})
	}
	group.Wait()
	if got := e.Snapshot(); got.Queued == 0 || got.Queued != got.Written || got.Failed != 0 || got.Pending != 0 || got.Dropped != 0 {
		t.Fatalf("incoherent concurrent topology accounting: %+v", got)
	}
}

// One flush may queue at most half of the queue as summaries.
func TestExporterTopologyBurstIsHalfOfTheQueue(t *testing.T) {
	for capacity, want := range map[int]int{1: 1, 2: 1, 3: 1, 16: 8, 1024: 512, MaxQueueCapacity: MaxQueueCapacity / 2} {
		sender := &exporterTestSender{closed: make(chan struct{}), send: func(context.Context, *pack.TagCountPack) error { return nil }}
		e, err := NewExporter(sender, ExporterConfig{NodeName: "node", QueueCapacity: capacity, DrainTimeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		if got := e.TopologyBurst(); got != want {
			t.Errorf("queue %d: burst %d; want %d", capacity, got, want)
		}
		if err := e.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
