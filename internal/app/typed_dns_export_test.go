package app

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/dns"
	"github.com/whatap/agentkubenetwork/internal/flow"
)

func TestEventOutputExportsDNSWithoutInventingLatency(t *testing.T) {
	for _, outcome := range []string{dns.OutcomeResponse, dns.OutcomeNoResponse, dns.OutcomeIncomplete, dns.OutcomeParseError} {
		t.Run(outcome, func(t *testing.T) {
			at := time.Date(2026, 9, 16, 1, 0, 0, 0, time.UTC)
			exporter := &recordingTypedExporter{recordingWindowExporter: recordingWindowExporter{failed: make(chan struct{})}}
			var output bytes.Buffer
			encoder, err := newEventOutput(&output, "node", func() time.Time { return at }, EventOptions{OutputMode: "windows", WindowExporter: exporter})
			if err != nil {
				t.Fatal(err)
			}
			tx := dns.Transaction{SchemaVersion: dns.SchemaVersion, ObservedAt: at, NodeName: "node", Protocol: "udp", Client: flow.Endpoint{Address: "0.0.0.0", Port: 40100}, Server: flow.Endpoint{Address: "10.0.0.53", Port: 53}, Outcome: outcome, QueryName: "service.ns.svc.cluster.local", QueryType: "A"}
			if outcome == dns.OutcomeResponse {
				tx.ResponseCode = "NOERROR"
				tx.LatencyMicros = 1700
				tx.LatencyMeasured = true
			}
			if err := encoder.Encode(tx); err != nil {
				t.Fatal(err)
			}
			if err := encoder.Close(); err != nil {
				t.Fatal(err)
			}
			if len(exporter.dns) != 1 {
				t.Fatalf("DNS record was not exported: got %d", len(exporter.dns))
			}
			got := exporter.dns[0]
			if got.Outcome != outcome || got.LatencyMicros != tx.LatencyMicros || got.LatencyMeasured != tx.LatencyMeasured || got.ResponseCode != tx.ResponseCode {
				t.Fatal("DNS outcome semantics changed")
			}
			var raw dns.Transaction
			if err := json.NewDecoder(&output).Decode(&raw); err != nil {
				t.Fatal(err)
			}
			if raw.Outcome != outcome || raw.LatencyMeasured != tx.LatencyMeasured || len(exporter.windows) != 0 {
				t.Fatal("DNS evidence was changed into an L4 window")
			}
		})
	}
}
