package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
)

func TestRunAggregatesJSONLObservationsIntoWindows(t *testing.T) {
	base := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	key := flow.FlowKey{
		NodeName:    "worker-a",
		Protocol:    "tcp",
		Direction:   "egress",
		Source:      flow.Endpoint{Address: "10.0.0.10", Port: 32000},
		Destination: flow.Endpoint{Address: "10.0.0.20", Port: 8080},
	}

	var input bytes.Buffer
	encoder := json.NewEncoder(&input)
	for _, observation := range []flow.Observation{
		{
			ObservedAt: base.Add(time.Second),
			Flow:       key,
			BytesTx:    100,
			RTT:        flow.Distribution{Count: 1, SumMicros: 1_000, MinMicros: 1_000, MaxMicros: 1_000},
		},
		{
			ObservedAt: base.Add(4 * time.Second),
			Flow:       key,
			BytesTx:    900,
			RTT:        flow.Distribution{Count: 9, SumMicros: 90_000, MinMicros: 10_000, MaxMicros: 10_000},
		},
	} {
		if err := encoder.Encode(observation); err != nil {
			t.Fatalf("encode input: %v", err)
		}
	}

	var output bytes.Buffer
	if err := Run(&input, &output, 5*time.Second); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	decoder := json.NewDecoder(&output)
	var window flow.Window
	if err := decoder.Decode(&window); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if window.BytesTx != 1_000 || window.RTT.Count != 10 || window.RTT.MeanMicros() != 9_100 {
		t.Fatalf("unexpected window: %+v, mean=%d", window, window.RTT.MeanMicros())
	}
	if err := decoder.Decode(&flow.Window{}); !errors.Is(err, io.EOF) {
		t.Fatalf("expected exactly one output window, got %v", err)
	}
}
