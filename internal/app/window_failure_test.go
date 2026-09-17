package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/bridge"
	"github.com/whatap/agentkubenetwork/internal/flow"
)

// This validates actual conversion without starting a sender or any network IO.
type validatingWindowExporter struct {
	calls int
}

func (e *validatingWindowExporter) Export(w flow.Window) error {
	e.calls++
	_, err := bridge.RequestForWindow(w)
	return err
}
func (*validatingWindowExporter) Failed() <-chan struct{} { return nil }
func (*validatingWindowExporter) Err() error              { return nil }
func (*validatingWindowExporter) Dropped() uint64         { return 0 }

func TestRejectedBatchRetainsRemainingJSONLWithoutMoreExports(t *testing.T) {
	for _, finalizing := range []bool{false, true} {
		t.Run(map[bool]string{false: "flush", true: "close"}[finalizing], func(t *testing.T) {
			start := time.Date(2026, 9, 15, 7, 37, 35, 0, time.UTC)
			clock := start.Add(6 * time.Second)
			var output bytes.Buffer
			exporter := &validatingWindowExporter{}
			encoder, err := newEventOutput(&output, "node", func() time.Time { return clock }, EventOptions{
				OutputMode: "windows", WindowSize: 5 * time.Second, WindowExporter: exporter,
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, port := range []uint16{0, 1, 2} {
				observation := flow.Observation{ObservedAt: start.Add(time.Second),
					Flow: flow.FlowKey{NodeName: "node", Protocol: "tcp", Direction: "connection",
						Source:      flow.Endpoint{Address: "10.0.0.1", Port: port},
						Destination: flow.Endpoint{Address: "10.0.0.2", Port: 8080}},
					RTT: flow.Distribution{Count: 1, SumMicros: 25, MinMicros: 25, MaxMicros: 25},
				}
				if err := encoder.Encode(observation); err != nil {
					t.Fatal(err)
				}
			}
			var result error
			if finalizing {
				result = encoder.Close()
			} else {
				result = encoder.Flush(clock)
				if err := encoder.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if result == nil {
				t.Fatal("invalid batch must still fail closed")
			}
			if exporter.calls != 1 {
				t.Fatalf("export continued after rejection: calls=%d", exporter.calls)
			}
			decoder := json.NewDecoder(&output)
			for _, port := range []uint16{0, 1, 2} {
				var got flow.Window
				if err := decoder.Decode(&got); err != nil {
					t.Fatalf("drained batch lost port %d: %v", port, err)
				}
				if got.Flow.Source.Port != port || got.Partial {
					t.Fatalf("changed completed window: %+v", got)
				}
			}
		})
	}
}

func TestRejectedCompletedWindowRetainsJSONLEvidence(t *testing.T) {
	start := time.Date(2026, 9, 15, 7, 37, 35, 0, time.UTC)
	clock := start.Add(6 * time.Second)
	var output bytes.Buffer
	exporter := &validatingWindowExporter{}
	encoder, err := newEventOutput(&output, "node", func() time.Time { return clock }, EventOptions{
		OutputMode: "windows", WindowSize: 5 * time.Second, WindowExporter: exporter,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Synthetic invalid input: not claimed to be the missing canary row.
	observation := flow.Observation{ObservedAt: start.Add(time.Second),
		Flow: flow.FlowKey{NodeName: "node", Protocol: "tcp", Direction: "connection",
			Source:      flow.Endpoint{Address: "10.0.0.1", Port: 0},
			Destination: flow.Endpoint{Address: "10.0.0.2", Port: 8080}},
		RTT: flow.Distribution{Count: 1, SumMicros: 25, MinMicros: 25, MaxMicros: 25},
	}
	if err := encoder.Encode(observation); err != nil {
		t.Fatal(err)
	}
	flushErr := encoder.Flush(clock)
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	if flushErr == nil {
		t.Fatal("invalid window must still fail closed")
	}
	var got flow.Window
	if err := json.NewDecoder(&output).Decode(&got); err != nil {
		t.Fatalf("rejected completed window missing from JSONL: %v", err)
	}
	if got.Partial || got.Flow != observation.Flow || got.RTT != observation.RTT || !got.WindowEnd.Equal(start.Add(5*time.Second)) {
		t.Fatalf("rejected window evidence was changed: %+v", got)
	}
	_, validationErr := bridge.RequestForWindow(got)
	if validationErr == nil || !errors.Is(flushErr, validationErr) && flushErr.Error() != "export flow window: "+validationErr.Error() {
		t.Fatalf("retained evidence does not reproduce validation failure: %v", validationErr)
	}
}
