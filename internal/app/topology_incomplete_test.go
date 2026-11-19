package app

import (
	"io"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
)

func TestTopologyDoesNotTerminateOnIncompleteDiagnosticL4Tuple(t *testing.T) {
	at := time.Date(2026, 9, 17, 0, 0, 1, 0, time.UTC)
	exporter := &recordingTopologyExporter{}
	encoder, err := newEventOutput(io.Discard, "node", func() time.Time { return at.Add(5 * time.Second) }, topologyTestOptions(exporter))
	if err != nil {
		t.Fatal(err)
	}
	observation := flow.Observation{ObservedAt: at, Flow: topologyTestHTTP(at).Flow,
		RTT: flow.Distribution{Count: 1, SumMicros: 1, MinMicros: 1, MaxMicros: 1}}
	observation.Flow.Direction = "connection"
	observation.Flow.Source.Port = 0
	if err := encoder.Encode(observation); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatalf("optional topology broke diagnostic collection: %v", err)
	}
	if len(exporter.summaries) != 0 || len(exporter.windows) != 1 {
		t.Fatal("incomplete tuple invented summary or lost diagnostic window")
	}
}
