package tagcount

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
	"github.com/whatap/golib/lang/pack"
)

type exporterTestSender struct {
	send      func(context.Context, *pack.TagCountPack) error
	closeOnce sync.Once
	closed    chan struct{}
}

func (s *exporterTestSender) Identity() (int64, int32) { return 123, 456 }
func (s *exporterTestSender) Send(ctx context.Context, p *pack.TagCountPack) error {
	return s.send(ctx, p)
}
func (s *exporterTestSender) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func exporterTestWindow() flow.Window {
	start := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	return flow.Window{
		SchemaVersion: flow.SchemaVersion, WindowStart: start, WindowEnd: start.Add(5 * time.Second),
		Flow: flow.FlowKey{NodeName: "node", Protocol: "tcp", Direction: "egress",
			Source: flow.Endpoint{Address: "10.0.0.1", Port: 40000}, Destination: flow.Endpoint{Address: "10.0.0.2", Port: 8080}},
		RTT: flow.Distribution{Count: 2, SumMicros: 40, MinMicros: 10, MaxMicros: 30},
	}
}

func TestExporterDrainsOnlyMeasuredCompleteWindows(t *testing.T) {
	var sent []*pack.TagCountPack
	sender := &exporterTestSender{closed: make(chan struct{}), send: func(_ context.Context, p *pack.TagCountPack) error {
		sent = append(sent, p)
		return nil
	}}
	exporter, err := NewExporter(sender, ExporterConfig{NodeName: "node", QueueCapacity: 4, DrainTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	w := exporterTestWindow()
	w.Process = &flow.Process{ContainerID: "container-before", Cmdline: "must-not-leak"}
	if err := exporter.Export(w); err != nil {
		t.Fatal(err)
	}
	w.Process.ContainerID = "container-after"
	w.Partial = true
	if err := exporter.Export(w); err != nil {
		t.Fatal(err)
	}
	w.Partial, w.RTT = false, flow.Distribution{}
	if err := exporter.Export(w); err != nil {
		t.Fatal(err)
	}
	if err := exporter.Close(); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 1 || sent[0].Tags.GetString("observer_container_id") != "container-before" || sent[0].Pcode != 123 || sent[0].Oid != 456 {
		t.Fatalf("unexpected sent snapshot: %v", sent)
	}
	summary := exporter.Snapshot()
	if summary.Queued != 1 || summary.Written != 1 || summary.Failed != 0 || summary.Dropped != 0 || summary.Pending != 0 || summary.SkippedPartial != 1 || summary.SkippedUnmeasured != 1 || summary.Stage != "tcp_write" {
		t.Fatalf("incorrect summary: %+v", summary)
	}
	if err := exporter.Close(); err != nil {
		t.Fatalf("Close is not idempotent: %v", err)
	}
	if err := exporter.Export(exporterTestWindow()); !errors.Is(err, ErrClosed) {
		t.Fatalf("export after Close = %v", err)
	}
	select {
	case <-sender.closed:
	default:
		t.Fatal("sender not closed")
	}
}

func TestExporterQueueIsBoundedAndDoesNotBlockCollection(t *testing.T) {
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
		exporter, err := NewExporter(sender, ExporterConfig{NodeName: "node", QueueCapacity: 1, DrainTimeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		if err := exporter.Export(exporterTestWindow()); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		for i := 0; i < 10; i++ {
			if err := exporter.Export(exporterTestWindow()); err != nil {
				t.Fatal(err)
			}
		}
		summary := exporter.Snapshot()
		if summary.Queued != 2 || summary.Dropped != 9 || summary.Written != 0 || summary.Pending != 2 {
			t.Fatalf("queue was not bounded: %+v", summary)
		}
		close(release)
		if err := exporter.Close(); !errors.Is(err, ErrQueueLoss) {
			t.Fatalf("Close hid queue loss: %v", err)
		}
		if summary = exporter.Snapshot(); summary.Written != 2 || summary.Pending != 0 || summary.Dropped != 9 {
			t.Fatalf("drain accounting: %+v", summary)
		}
	})
}

func TestExporterFailureIsTerminalWithoutRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		calls := 0
		sender := &exporterTestSender{closed: make(chan struct{}), send: func(_ context.Context, _ *pack.TagCountPack) error {
			calls++
			<-release
			return io.ErrUnexpectedEOF
		}}
		exporter, err := NewExporter(sender, ExporterConfig{NodeName: "node", QueueCapacity: 4, DrainTimeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			if err := exporter.Export(exporterTestWindow()); err != nil {
				t.Fatal(err)
			}
		}
		close(release)
		<-exporter.Failed()
		if !errors.Is(exporter.Err(), io.ErrUnexpectedEOF) || !errors.Is(exporter.Export(exporterTestWindow()), io.ErrUnexpectedEOF) {
			t.Fatal("export failure was not propagated")
		}
		if err := exporter.Close(); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("Close failure = %v", err)
		}
		summary := exporter.Snapshot()
		if calls != 1 || summary.Queued != 3 || summary.Failed != 1 || summary.Pending != 2 || summary.Written != 0 {
			t.Fatalf("failed data was retried or miscounted: calls=%d summary=%+v", calls, summary)
		}
	})
}

func TestExporterDrainDeadlineCancelsAndClosesSender(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sender := &exporterTestSender{closed: make(chan struct{}), send: func(ctx context.Context, _ *pack.TagCountPack) error {
			<-ctx.Done()
			return ctx.Err()
		}}
		exporter, err := NewExporter(sender, ExporterConfig{NodeName: "node", QueueCapacity: 2, DrainTimeout: 100 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		if err := exporter.Export(exporterTestWindow()); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		started := time.Now()
		if err := exporter.Close(); !errors.Is(err, ErrDrainTimeout) {
			t.Fatalf("Close did not report timeout: %v", err)
		}
		if time.Since(started) != 100*time.Millisecond {
			t.Fatalf("unbounded drain: %v", time.Since(started))
		}
		synctest.Wait()
		select {
		case <-sender.closed:
		default:
			t.Fatal("timed out sender was not closed")
		}
		select {
		case <-exporter.done:
		default:
			t.Fatal("export worker survived cancellation")
		}
	})
}

func TestExporterRejectsInvalidLimitsAndForeignNode(t *testing.T) {
	sender := &exporterTestSender{closed: make(chan struct{}), send: func(context.Context, *pack.TagCountPack) error { return nil }}
	for _, config := range []ExporterConfig{
		{NodeName: "node", QueueCapacity: 0, DrainTimeout: time.Second},
		{NodeName: "node", QueueCapacity: MaxQueueCapacity + 1, DrainTimeout: time.Second},
		{NodeName: "node", QueueCapacity: 1, DrainTimeout: 0},
		{NodeName: "", QueueCapacity: 1, DrainTimeout: time.Second},
	} {
		if exporter, err := NewExporter(sender, config); err == nil {
			exporter.Close()
			t.Fatalf("accepted invalid limits: %+v", config)
		}
	}
	exporter, err := NewExporter(sender, ExporterConfig{NodeName: "node", QueueCapacity: 1, DrainTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Close()
	w := exporterTestWindow()
	w.Flow.NodeName = "another-node"
	if err := exporter.Export(w); err == nil {
		t.Fatal("accepted a foreign observer node")
	}
	if got := exporter.Snapshot().Queued; got != 0 {
		t.Fatalf("invalid window queued: %d", got)
	}
}

func TestExporterConcurrentCloseAndExport(t *testing.T) {
	sender := &exporterTestSender{closed: make(chan struct{}), send: func(context.Context, *pack.TagCountPack) error { return nil }}
	exporter, err := NewExporter(sender, ExporterConfig{NodeName: "node", QueueCapacity: 32, DrainTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Go(func() {
			for j := 0; j < 20; j++ {
				if err := exporter.Export(exporterTestWindow()); err != nil && !errors.Is(err, ErrClosed) {
					t.Errorf("Export: %v", err)
				}
				exporter.Snapshot()
			}
		})
	}
	group.Go(func() { exporter.Close() })
	group.Go(func() { exporter.Close() })
	group.Wait()
	summary := exporter.Snapshot()
	if summary.Queued != summary.Written+summary.Failed+summary.Pending || summary.Pending != 0 {
		t.Fatalf("incoherent concurrent summary: %+v", summary)
	}
}
