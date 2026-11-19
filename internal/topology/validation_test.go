package topology

import (
	"strings"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
)

func TestL4RejectsMalformedObservationsWithoutMutatingState(t *testing.T) {
	for name, change := range map[string]func(*flow.Window){
		"zero input":            func(w *flow.Window) { *w = flow.Window{} },
		"wrong schema":          func(w *flow.Window) { w.SchemaVersion = "other" },
		"wrong transport":       func(w *flow.Window) { w.Flow.Protocol = "udp" },
		"no observations":       func(w *flow.Window) { w.ObservationCount = 0 },
		"no actual time":        func(w *flow.Window) { w.LastObservedAt = time.Time{} },
		"last before window":    func(w *flow.Window) { w.LastObservedAt = w.WindowStart.Add(-time.Nanosecond) },
		"last at exclusive end": func(w *flow.Window) { w.LastObservedAt = w.WindowEnd },
		"bad window":            func(w *flow.Window) { w.WindowEnd = w.WindowStart },
		"no start":              func(w *flow.Window) { w.WindowStart = time.Time{} },
		"overflow time": func(w *flow.Window) {
			w.LastObservedAt = time.Unix(1<<62, 0)
			w.WindowEnd = w.LastObservedAt.Add(time.Second)
		},
		"empty source":          func(w *flow.Window) { w.Flow.Source = flow.Endpoint{} },
		"hostname source":       func(w *flow.Window) { w.Flow.Source.Address = "client.example" },
		"unspecified source":    func(w *flow.Window) { w.Flow.Source.Address = "0.0.0.0" },
		"multicast destination": func(w *flow.Window) { w.Flow.Destination.Address = "ff02::1" },
		"zone address":          func(w *flow.Window) { w.Flow.Source.Address = "fe80::1%en0" },
		"zero raw port":         func(w *flow.Window) { w.Flow.Destination.Port = 0 },
		"malformed resolved": func(w *flow.Window) {
			w.SourceResolved = &flow.ResolvedEndpoint{Address: "bad", Port: 8080, Via: "conntrack"}
		},
		"unspecified resolved": func(w *flow.Window) {
			w.DestinationResolved = &flow.ResolvedEndpoint{Address: "::", Port: 8080, Via: "conntrack"}
		},
		"unproven resolved":  func(w *flow.Window) { w.SourceResolved = &flow.ResolvedEndpoint{Address: "10.0.0.9", Port: 8080} },
		"malformed workload": func(w *flow.Window) { w.SourcePod = workloadPod("client"); w.SourcePod.WorkloadName = "bad\nname" },
		"oversize uid": func(w *flow.Window) {
			w.SourcePod = workloadPod("client")
			w.SourcePod.WorkloadUID = strings.Repeat("x", 254)
		},
	} {
		t.Run(name, func(t *testing.T) {
			a, err := New(Config{ClusterID: "cluster-a", WindowSize: time.Minute, MaxEntries: 1})
			if err != nil {
				t.Fatal(err)
			}
			w := testWindow(testStart.Add(time.Second))
			change(&w)
			if err := a.ObserveWindow(w); err == nil {
				t.Fatal("accepted malformed input")
			}
			if a.Len() != 0 || len(a.FlushAll()) != 0 {
				t.Fatal("invalid input polluted state")
			}
		})
	}
}
