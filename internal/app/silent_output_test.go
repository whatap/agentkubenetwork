package app

import (
	"bytes"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/dns"
	"github.com/whatap/agentkubenetwork/internal/flow"
	"github.com/whatap/agentkubenetwork/internal/l7"
)

func TestSilentOutputSkipsSerializationAndQueue(t *testing.T) {
	q, err := newQueuedOutput(io.Discard, "node", time.Now, 1, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if err := q.Encode(make(chan int)); err != nil {
		t.Fatalf("silent output serialized body: %v", err)
	}
	if q.queue != nil {
		t.Fatal("silent output allocated a telemetry queue")
	}
}

func TestSilentPipelinePreservesTypedExportAndWindows(t *testing.T) {
	at := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	for _, mode := range []string{"windows", "both"} {
		var reference *recordingTypedExporter
		for _, silent := range []bool{false, true} {
			var output bytes.Buffer
			var writer io.Writer = &output
			if silent {
				writer = io.Discard
			}
			exporter := &recordingTypedExporter{recordingWindowExporter: recordingWindowExporter{failed: make(chan struct{})}}
			e, err := newEventOutput(writer, "node", func() time.Time { return at.Add(8 * time.Second) }, EventOptions{OutputMode: mode, WindowSize: 5 * time.Second, WindowExporter: exporter})
			if err != nil {
				t.Fatal(err)
			}
			obs := flow.Observation{ObservedAt: at.Add(time.Second), Flow: flow.FlowKey{NodeName: "node", Protocol: "tcp", Source: flow.Endpoint{Address: "10.0.0.1", Port: 40000}, Destination: flow.Endpoint{Address: "10.0.0.2", Port: 8080}}, RTT: flow.Distribution{Count: 1, SumMicros: 25, MinMicros: 25, MaxMicros: 25}}
			for _, record := range []any{obs, l7.Transaction{ObservedAt: at, Method: "GET", StatusCode: 200, ResponseLatencyMicros: 1200}, dns.Transaction{ObservedAt: at, Outcome: dns.OutcomeResponse, QueryName: "private.example", LatencyMeasured: true, LatencyMicros: 1700}, l7.Drop{}} {
				if err := e.Encode(record); err != nil {
					t.Fatal(err)
				}
			}
			if err := e.Flush(at.Add(6 * time.Second)); err != nil {
				t.Fatal(err)
			}
			obs.ObservedAt = at.Add(7 * time.Second)
			if err := e.Encode(obs); err != nil {
				t.Fatal(err)
			}
			if err := e.Close(); err != nil {
				t.Fatal(err)
			}
			if len(exporter.windows) != 2 || len(exporter.http) != 1 || len(exporter.dns) != 1 || len(exporter.drops) != 1 {
				t.Fatalf("lost export: %+v", exporter)
			}
			if silent {
				if output.Len() != 0 || !reflect.DeepEqual(exporter.windows, reference.windows) || !reflect.DeepEqual(exporter.http, reference.http) || !reflect.DeepEqual(exporter.dns, reference.dns) || !reflect.DeepEqual(exporter.drops, reference.drops) {
					t.Fatal("stdout suppression altered exports")
				}
			} else {
				if output.Len() == 0 {
					t.Fatal("JSONL missing")
				}
				reference = exporter
			}
		}
	}
}
