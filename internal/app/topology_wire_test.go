package app

import (
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
	"github.com/whatap/agentkubenetwork/internal/tagcount"
	"github.com/whatap/golib/lang/pack"
)

type topologyWireSender struct {
	mu     sync.Mutex
	frames [][]byte
}

func (*topologyWireSender) Identity() (int64, int32) { return 1, 2 }
func (*topologyWireSender) Close() error             { return nil }
func (s *topologyWireSender) Send(_ context.Context, p *pack.TagCountPack) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.frames = append(s.frames, pack.ToBytesPack(p))
	return nil
}

// The real bounded exporter and production wire codec are exercised here.
// The sink is local and does not claim collector ACK or stored backend data.
func TestTopologyPipelineProductionWireRetainsDetailAndCollapsesReplicas(t *testing.T) {
	at := time.Date(2026, 9, 17, 0, 0, 1, 0, time.UTC)
	sender := &topologyWireSender{}
	exporter, err := tagcount.NewExporter(sender, tagcount.ExporterConfig{NodeName: "node", QueueCapacity: 256, DrainTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exporter.Close() })
	encoder, err := newEventOutput(io.Discard, "node", func() time.Time { return at }, topologyTestOptions(exporter))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		tx := topologyTestHTTP(at.Add(time.Duration(i) * time.Millisecond))
		tx.Flow.Source.Address = fmt.Sprintf("10.0.1.%d", i+1)
		tx.Flow.Source.Port += uint16(i)
		tx.SourcePod = &flow.Pod{UID: fmt.Sprintf("pod-%d", i), Namespace: "a", Name: fmt.Sprintf("client-%d", i), WorkloadUID: "client-uid", WorkloadKind: "Deployment", WorkloadName: "client"}
		tx.DestinationPod = &flow.Pod{UID: "server-pod", Namespace: "b", Name: "server-pod", WorkloadUID: "server-uid", WorkloadKind: "Deployment", WorkloadName: "server"}
		if i == 50 {
			tx.StatusCode = 503
		}
		if err := encoder.Encode(tx); err != nil {
			t.Fatal(err)
		}
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	// RunEventsWithOptions owns the exporter's drain after eventOutput closes.
	if err := exporter.Close(); err != nil {
		t.Fatal(err)
	}
	sender.mu.Lock()
	defer sender.mu.Unlock()
	counts := map[string]int{}
	for _, wire := range sender.frames {
		p, ok := pack.ToPack(wire).(*pack.TagCountPack)
		if !ok {
			t.Fatal("invalid TagCount wire")
		}
		counts[p.Category]++
		if p.Category == tagcount.TopologyCategory {
			if p.Data.GetLong("observed") != 1 || p.Data.GetLong("result_observed") != 1 || p.Data.GetLong("error_observed") != 1 {
				t.Fatalf("flags lost: %v", p.Data)
			}
			if p.Tags.GetString("src_uid") != "client-uid" || p.Tags.GetString("dst_uid") != "server-uid" {
				t.Fatalf("workload identity lost: %v", p.Tags)
			}
			for _, field := range []string{"record_id", "src_pod_uid", "dst_pod_uid", "src_addr", "observer_node", "src_port"} {
				if p.Tags.ContainsKey(field) {
					t.Fatalf("high-cardinality tag %s leaked", field)
				}
			}
		}
	}
	if counts[tagcount.HTTPCategory] != 100 || counts[tagcount.TopologyCategory] != 1 {
		t.Fatalf("wire record counts: %v", counts)
	}
	if summary := exporter.Snapshot(); summary.Dropped != 0 || summary.Failed != 0 || summary.Pending != 0 {
		t.Fatalf("wire queue incomplete: %+v", summary)
	}
}
