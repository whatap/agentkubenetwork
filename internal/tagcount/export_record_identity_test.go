package tagcount

import (
	"context"
	"testing"
	"time"

	"github.com/whatap/golib/lang/pack"
)

func TestExporterPreservesIdenticalCoverageObservationsInOneBatch(t *testing.T) {
	var sent []*pack.TagCountPack
	sender := &exporterTestSender{closed: make(chan struct{}), send: func(_ context.Context, p *pack.TagCountPack) error { sent = append(sent, p); return nil }}
	e, err := NewExporter(sender, ExporterConfig{NodeName: "node-a", QueueCapacity: 8, DrainTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	drop := sampleCoverageDrop()
	drop.NodeName = "node-a"
	for i := 0; i < 2; i++ {
		if err := e.ExportL7Drop(drop); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 2 {
		t.Fatalf("sent=%d", len(sent))
	}
	if sent[0].Tags.GetString("record_id") == sent[1].Tags.GetString("record_id") {
		t.Fatal("distinct coverage observations have the same storage record identity")
	}
}
