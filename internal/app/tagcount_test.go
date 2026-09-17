package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
)

type recordingWindowExporter struct {
	windows []flow.Window
	failed  chan struct{}
	err     error
	dropped uint64
}

func (e *recordingWindowExporter) Export(w flow.Window) error {
	e.windows = append(e.windows, w)
	return e.err
}
func (e *recordingWindowExporter) Failed() <-chan struct{} { return e.failed }
func (e *recordingWindowExporter) Err() error              { return e.err }
func (e *recordingWindowExporter) Dropped() uint64         { return e.dropped }

func TestEventOutputExportsOnlyAggregatedWindows(t *testing.T) {
	for _, mode := range []string{"windows", "both"} {
		t.Run(mode, func(t *testing.T) {
			start := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
			clock := start.Add(8 * time.Second)
			exporter := &recordingWindowExporter{failed: make(chan struct{})}
			var output bytes.Buffer
			encoder, err := newEventOutput(&output, "node", func() time.Time { return clock }, EventOptions{OutputMode: mode, WindowSize: 5 * time.Second, WindowExporter: exporter})
			if err != nil {
				t.Fatal(err)
			}
			observation := flow.Observation{ObservedAt: start.Add(time.Second),
				Flow: flow.FlowKey{NodeName: "node", Protocol: "tcp", Source: flow.Endpoint{Address: "10.0.0.1", Port: 40000}, Destination: flow.Endpoint{Address: "10.0.0.2", Port: 8080}},
				RTT:  flow.Distribution{Count: 1, SumMicros: 25, MinMicros: 25, MaxMicros: 25}}
			if err := encoder.Encode(observation); err != nil {
				t.Fatal(err)
			}
			if err := encoder.Encode(map[string]string{"schemaVersion": "network.dns/v1alpha1"}); err != nil {
				t.Fatal(err)
			}
			if len(exporter.windows) != 0 {
				t.Fatal("raw or DNS record was exported as a window")
			}
			if err := encoder.Flush(start.Add(6 * time.Second)); err != nil {
				t.Fatal(err)
			}
			observation.ObservedAt = start.Add(7 * time.Second)
			if err := encoder.Encode(observation); err != nil {
				t.Fatal(err)
			}
			if err := encoder.Close(); err != nil {
				t.Fatal(err)
			}
			if len(exporter.windows) != 2 || exporter.windows[0].Partial || !exporter.windows[1].Partial || exporter.windows[0].RTT.Count != 1 {
				t.Fatalf("incorrect flush/finalization: %+v", exporter.windows)
			}
			decoder := json.NewDecoder(&output)
			windows, dns := 0, 0
			for {
				var record struct {
					SchemaVersion string `json:"schemaVersion"`
				}
				if err := decoder.Decode(&record); errors.Is(err, io.EOF) {
					break
				} else if err != nil {
					t.Fatal(err)
				}
				switch record.SchemaVersion {
				case flow.SchemaVersion:
					windows++
				case "network.dns/v1alpha1":
					dns++
				}
			}
			if windows != 2 || dns != 1 {
				t.Fatalf("direct export changed JSONL: windows=%d dns=%d", windows, dns)
			}
		})
	}
}

func TestEventOutputRejectsRawModeWithWindowExporter(t *testing.T) {
	for _, mode := range []string{"", "raw"} {
		encoder, err := newEventOutput(io.Discard, "node", time.Now, EventOptions{OutputMode: mode, WindowExporter: &recordingWindowExporter{}})
		if err == nil {
			encoder.Close()
			t.Fatalf("mode %q silently disables requested export", mode)
		}
	}
}

func TestEventOutputReportsTagCountQueueLossDeltas(t *testing.T) {
	exporter := &recordingWindowExporter{failed: make(chan struct{}), dropped: 3}
	var output bytes.Buffer
	encoder, err := newEventOutput(&output, "node", time.Now, EventOptions{OutputMode: "windows", WindowExporter: exporter})
	if err != nil {
		t.Fatal(err)
	}
	if err := encoder.Flush(time.Now()); err != nil {
		t.Fatal(err)
	}
	exporter.dropped = 5
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&output)
	for _, want := range []struct{ count, total uint64 }{{3, 3}, {2, 5}} {
		var got struct {
			Schema string `json:"schemaVersion"`
			Reason string `json:"reason"`
			Count  uint64 `json:"droppedRecords"`
			Total  uint64 `json:"totalDroppedRecords"`
		}
		if err := decoder.Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.Schema != "network.tagcount.drop/v1alpha1" || got.Reason != "tagcount_queue_full" || got.Count != want.count || got.Total != want.total {
			t.Fatalf("loss delta not coherent: %+v", got)
		}
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		t.Fatalf("duplicate loss report: %v", err)
	}
}

func TestRunEventsStopsForWindowExporterFailureWhileIdle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reader := newChannelEventReader()
		exporter := &recordingWindowExporter{failed: make(chan struct{}), err: io.ErrUnexpectedEOF}
		result := make(chan error, 1)
		go func() {
			result <- RunEventsWithOptions(context.Background(), reader, io.Discard, "node", 0, time.Now, nil, nil, EventOptions{OutputMode: "windows", WindowExporter: exporter})
		}()
		synctest.Wait()
		close(exporter.failed)
		synctest.Wait()
		select {
		case err := <-result:
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("export error lost: %v", err)
			}
		default:
			t.Fatal("idle reader concealed an asynchronous export failure")
		}
		select {
		case <-reader.stop:
		default:
			t.Fatal("reader not stopped after export failure")
		}
	})
}
