package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/dns"
	"github.com/whatap/agentkubenetwork/internal/flow"
	"github.com/whatap/agentkubenetwork/internal/l7"
)

func TestTypedExportFailurePreservesRemainingEvidenceWithoutResubmission(t *testing.T) {
	at := time.Date(2026, 9, 16, 1, 0, 0, 0, time.UTC)
	want := errors.New("test-only export rejection")
	exporter := &recordingTypedExporter{recordingWindowExporter: recordingWindowExporter{failed: make(chan struct{})}, eventErr: want}
	var output bytes.Buffer
	encoder, err := newEventOutput(&output, "node", func() time.Time { return at.Add(8 * time.Second) }, EventOptions{OutputMode: "windows", WindowExporter: exporter})
	if err != nil {
		t.Fatal(err)
	}
	records := []any{
		l7.Transaction{SchemaVersion: l7.SchemaVersion, ObservedAt: at},
		dns.Transaction{SchemaVersion: dns.SchemaVersion, ObservedAt: at, Outcome: dns.OutcomeIncomplete},
		l7.Drop{SchemaVersion: l7.SchemaVersion, ObservedAt: at, Outcome: "drop", Reason: l7.DropResponseTimeout},
	}
	for _, record := range records {
		if err := encoder.Encode(record); !errors.Is(err, want) {
			t.Fatalf("lost export error: %v", err)
		}
	}
	observation := flow.Observation{ObservedAt: at.Add(time.Second), Flow: flow.FlowKey{NodeName: "node", Protocol: "tcp", Source: flow.Endpoint{Address: "10.0.0.1", Port: 40000}, Destination: flow.Endpoint{Address: "10.0.0.2", Port: 8080}}, RTT: flow.Distribution{Count: 1, SumMicros: 25, MinMicros: 25, MaxMicros: 25}}
	if err := encoder.Encode(observation); err != nil && !errors.Is(err, want) {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil && !errors.Is(err, want) {
		t.Fatal(err)
	}
	if len(exporter.http) != 1 || len(exporter.dns) != 0 || len(exporter.drops) != 0 || len(exporter.windows) != 0 {
		t.Fatalf("export continued after rejection: HTTP=%d DNS=%d coverage=%d windows=%d", len(exporter.http), len(exporter.dns), len(exporter.drops), len(exporter.windows))
	}
	decoder := json.NewDecoder(&output)
	count := 0
	for {
		var record map[string]any
		err := decoder.Decode(&record)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		count++
	}
	if count != 4 {
		t.Fatalf("remaining evidence lost after rejection: got %d", count)
	}
}
