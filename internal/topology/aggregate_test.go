package topology

import (
	"reflect"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
)

var testStart = time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)

func testWindow(at time.Time) flow.Window {
	start := at.Truncate(5 * time.Second)
	return flow.Window{
		SchemaVersion: flow.SchemaVersion,
		WindowStart:   start, WindowEnd: start.Add(5 * time.Second), LastObservedAt: at,
		ObservationCount: 1,
		Flow: flow.FlowKey{NodeName: "node-a", Protocol: "tcp", Direction: "connection",
			Source:      flow.Endpoint{Address: "10.0.0.2", Port: 42123},
			Destination: flow.Endpoint{Address: "10.0.0.1", Port: 8080}},
	}
}

func TestL4CanonicalPresenceCoalescesPortsAndObservers(t *testing.T) {
	a, err := New(Config{ClusterID: "cluster-a", WindowSize: time.Minute, MaxEntries: 4})
	if err != nil {
		t.Fatal(err)
	}
	w := testWindow(testStart.Add(time.Second))
	if err := a.ObserveWindow(w); err != nil {
		t.Fatal(err)
	}
	w.Flow.Source, w.Flow.Destination = w.Flow.Destination, w.Flow.Source
	w.Flow.Source.Port, w.Flow.Destination.Port = 8081, 52789
	w.Flow.NodeName, w.Flow.Direction = "another-observer", "egress"
	w.LastObservedAt = testStart.Add(2 * time.Second)
	w.Process = &flow.Process{PID: 987, ContainerID: "unrelated-observer"}
	if err := a.ObserveWindow(w); err != nil {
		t.Fatal(err)
	}
	if a.Len() != 1 {
		t.Fatalf("entries=%d, want one address relationship", a.Len())
	}
	if got := a.FlushBefore(testStart.Add(59 * time.Second)); len(got) != 0 {
		t.Fatalf("flushed incomplete bucket: %+v", got)
	}
	got := a.FlushBefore(testStart.Add(time.Minute))
	want := []Summary{{
		ClusterID: "cluster-a", WindowStart: testStart, WindowEnd: testStart.Add(time.Minute),
		Source:      Endpoint{Kind: "unresolved_address", Address: "10.0.0.1"},
		Destination: Endpoint{Kind: "unresolved_address", Address: "10.0.0.2"},
		Transport:   "tcp", Protocol: "tcp", Direction: "unknown",
		Observed: true, LastSeenMS: w.LastObservedAt.UnixMilli(),
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v; want %+v", got, want)
	}
	if a.Len() != 0 || len(a.FlushAll()) != 0 {
		t.Fatal("drain retained state")
	}
}
