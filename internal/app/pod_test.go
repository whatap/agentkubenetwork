package app

import (
	"bytes"
	"encoding/json"
	"github.com/whatap/agentkubenetwork/internal/flow"
	"github.com/whatap/agentkubenetwork/internal/tagcount"
	"io"
	"testing"
	"time"
)

type podEnricherFunc func(*flow.Observation)

func (f podEnricherFunc) Enrich(o *flow.Observation) { f(o) }
func TestPodEnrichmentBeforeAggregationAndRawWrapping(t *testing.T) {
	start := time.Unix(100, 0)
	var output bytes.Buffer
	exporter := &recordingWindowExporter{}
	uid := "old"
	encoder, err := newEventOutput(&output, "node", func() time.Time { return start.Add(time.Minute) }, EventOptions{OutputMode: "both", WindowSize: 5 * time.Second, WindowExporter: exporter, PodEnricher: podEnricherFunc(func(o *flow.Observation) {
		o.ObserverPod = &flow.Pod{UID: uid, Namespace: "ns", Name: "pod"}
		o.DestinationPod = &flow.Pod{UID: uid, Namespace: "ns", Name: "pod"}
	})})
	if err != nil {
		t.Fatal(err)
	}
	o := flow.Observation{ObservedAt: start, Flow: flow.FlowKey{NodeName: "node", Protocol: "tcp", Source: flow.Endpoint{Address: "10.0.0.1", Port: 1234}, Destination: flow.Endpoint{Address: "10.0.0.2", Port: 80}}, RTT: flow.Distribution{Count: 1, SumMicros: 10, MinMicros: 10, MaxMicros: 10}}
	if err := encoder.Encode(o); err != nil {
		t.Fatal(err)
	}
	uid = "new"
	if err := encoder.Encode(resolvedObservation{Observation: o}); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Flush(start.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	if len(exporter.windows) != 2 {
		t.Fatalf("UID merged before export: %+v", exporter.windows)
	}
	for _, w := range exporter.windows {
		p, err := tagcount.PackForWindow(w, 1, 1)
		if err != nil {
			t.Fatal(err)
		}
		if p.Tags.GetString("observer_pod_uid") != w.ObserverPod.UID || p.Tags.GetString("dst_pod_uid") != w.DestinationPod.UID {
			t.Fatal("TagCount dropped UID")
		}
	}
	dec := json.NewDecoder(&output)
	count := 0
	for {
		var raw map[string]any
		err := dec.Decode(&raw)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if raw["observerPod"] == nil || raw["destinationPod"] == nil {
			t.Fatalf("raw/window lost UID: %+v", raw)
		}
		count++
	}
	if count != 4 {
		t.Fatalf("records %d", count)
	}
}
