package app

import (
	"bytes"
	"encoding/json"
	"github.com/whatap/agentkubenetwork/internal/l7"
	"testing"
	"time"
)

func TestEventOutputExportsCoverageSeparatelyFromRequests(t *testing.T) {
	at := time.Date(2026, 9, 16, 1, 0, 0, 0, time.UTC)
	exporter := &recordingTypedExporter{recordingWindowExporter: recordingWindowExporter{failed: make(chan struct{})}}
	var output bytes.Buffer
	encoder, err := newEventOutput(&output, "node", func() time.Time { return at }, EventOptions{OutputMode: "windows", WindowExporter: exporter})
	if err != nil {
		t.Fatal(err)
	}
	drop := l7.Drop{SchemaVersion: l7.SchemaVersion, ObservedAt: at, NodeName: "node", Protocol: l7.ProtocolHTTP1, Source: string(l7.SourceKernelPlaintext), Outcome: "drop", Reason: l7.DropResponseTimeout, Count: 3}
	if err := encoder.Encode(drop); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	if len(exporter.drops) != 1 {
		t.Fatalf("coverage was not exported: got %d", len(exporter.drops))
	}
	if len(exporter.http) != 0 || len(exporter.dns) != 0 || len(exporter.windows) != 0 {
		t.Fatal("coverage became a customer request or latency")
	}
	var got l7.Drop
	if err := json.NewDecoder(&output).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Reason != drop.Reason || got.Count != drop.Count || exporter.drops[0].Count != drop.Count {
		t.Fatal("coverage semantics changed")
	}
}
