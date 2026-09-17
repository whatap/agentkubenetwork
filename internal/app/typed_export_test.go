package app

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/dns"
	"github.com/whatap/agentkubenetwork/internal/flow"
	"github.com/whatap/agentkubenetwork/internal/l7"
)

type recordingTypedExporter struct {
	recordingWindowExporter
	http     []l7.Transaction
	dns      []dns.Transaction
	drops    []l7.Drop
	eventErr error
}

func (e *recordingTypedExporter) ExportL7(v l7.Transaction) error {
	e.http = append(e.http, v)
	return e.eventErr
}
func (e *recordingTypedExporter) ExportDNS(v dns.Transaction) error {
	e.dns = append(e.dns, v)
	return e.eventErr
}
func (e *recordingTypedExporter) ExportL7Drop(v l7.Drop) error {
	e.drops = append(e.drops, v)
	return e.eventErr
}

func TestEventOutputExportsHTTPAsTypedTransaction(t *testing.T) {
	for _, pointer := range []bool{false, true} {
		t.Run(map[bool]string{false: "value", true: "pointer"}[pointer], func(t *testing.T) {
			at := time.Date(2026, 9, 16, 1, 0, 0, 0, time.UTC)
			exporter := &recordingTypedExporter{recordingWindowExporter: recordingWindowExporter{failed: make(chan struct{})}}
			var output bytes.Buffer
			encoder, err := newEventOutput(&output, "node", func() time.Time { return at }, EventOptions{OutputMode: "windows", WindowExporter: exporter})
			if err != nil {
				t.Fatal(err)
			}
			tx := l7.Transaction{SchemaVersion: l7.SchemaVersion, ObservedAt: at, Protocol: l7.ProtocolHTTP1, Source: l7.SourceKernelPlaintext, Method: "GET", StatusCode: 200, ResponseLatencyMicros: 1200, LatencyBoundary: l7.BoundaryResponseHeaders, Flow: flow.FlowKey{NodeName: "node", Protocol: "tcp", Direction: "client-to-server", Source: flow.Endpoint{Address: "10.0.0.1", Port: 40000}, Destination: flow.Endpoint{Address: "10.0.0.2", Port: 8080}}}
			var record any = tx
			if pointer {
				record = &tx
			}
			if err := encoder.Encode(record); err != nil {
				t.Fatal(err)
			}
			if err := encoder.Close(); err != nil {
				t.Fatal(err)
			}
			if len(exporter.http) != 1 {
				t.Fatalf("HTTP transaction was not exported: got %d", len(exporter.http))
			}
			if len(exporter.windows) != 0 {
				t.Fatal("HTTP was coerced into an L4 window")
			}
			var got l7.Transaction
			if err := json.NewDecoder(&output).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if got.ResponseLatencyMicros != tx.ResponseLatencyMicros || exporter.http[0].ResponseLatencyMicros != tx.ResponseLatencyMicros {
				t.Fatal("HTTP latency was changed")
			}
		})
	}
}
