package tagcount

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/dns"
	"github.com/whatap/agentkubenetwork/internal/flow"
	"github.com/whatap/agentkubenetwork/internal/l7"
	"github.com/whatap/golib/lang/pack"
)

type testTypedExporter interface {
	ExportL7(l7.Transaction) error
	ExportDNS(dns.Transaction) error
	ExportL7Drop(l7.Drop) error
}

func TestExporterDrainsAllTelemetryKindsThroughOneBoundedQueue(t *testing.T) {
	var sent []*pack.TagCountPack
	sender := &exporterTestSender{closed: make(chan struct{}), send: func(_ context.Context, p *pack.TagCountPack) error { sent = append(sent, p); return nil }}
	exporter, err := NewExporter(sender, ExporterConfig{NodeName: "node-a", QueueCapacity: 8, DrainTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Close()
	typed, ok := any(exporter).(testTypedExporter)
	if !ok {
		t.Fatal("TagCount exporter has no typed HTTP/DNS/coverage path")
	}
	http := eventHTTP()
	http.Process = &flow.Process{ContainerID: "before-export"}
	dnsTx := eventDNS()
	drop := sampleCoverageDrop()
	drop.NodeName = "node-a"
	window := exporterTestWindow()
	window.Flow.NodeName = "node-a"
	if err := typed.ExportL7(http); err != nil {
		t.Fatal(err)
	}
	http.Process.ContainerID = "after-export"
	if err := typed.ExportDNS(dnsTx); err != nil {
		t.Fatal(err)
	}
	if err := typed.ExportL7Drop(drop); err != nil {
		t.Fatal(err)
	}
	if err := exporter.Export(window); err != nil {
		t.Fatal(err)
	}
	if err := exporter.Close(); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 4 {
		t.Fatalf("sent=%d, want 4 telemetry records", len(sent))
	}
	want := []string{HTTPCategory, DNSCategory, CoverageCategory, Category}
	for i, p := range sent {
		if p.Category != want[i] || p.Pcode != 123 || p.Oid != 456 {
			t.Fatalf("wrong telemetry envelope at %d", i)
		}
	}
	if sent[0].Tags.GetString("observer_container_id") != "before-export" {
		t.Fatal("queued HTTP observation was aliased")
	}
	summary := exporter.Snapshot()
	if summary.Queued != 4 || summary.Written != 4 || summary.Failed != 0 || summary.Pending != 0 || summary.Dropped != 0 {
		t.Fatalf("bad shared queue accounting: %+v", summary)
	}
	for _, err := range []error{typed.ExportL7(http), typed.ExportDNS(dnsTx), typed.ExportL7Drop(drop)} {
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("typed export after close: %v", err)
		}
	}
}
