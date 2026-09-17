package tagcount

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
	"github.com/whatap/golib/lang/pack"
)

func TestExporterSkipsIncompleteTCPTupleAndContinues(t *testing.T) {
	for _, missing := range []string{"source", "destination"} {
		t.Run(missing, func(t *testing.T) {
			var sent []*pack.TagCountPack
			sender := &exporterTestSender{closed: make(chan struct{}), send: func(_ context.Context, p *pack.TagCountPack) error {
				sent = append(sent, p)
				return nil
			}}
			exporter, err := NewExporter(sender, ExporterConfig{NodeName: "node", QueueCapacity: 4, DrainTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer exporter.Close()
			bad := exporterTestWindow()
			bad.Flow.Direction = "connection"
			bad.RTT = flow.Distribution{Count: 1, SumMicros: 151, MinMicros: 151, MaxMicros: 151}
			if missing == "source" {
				bad.Flow.Source.Port = 0
			} else {
				bad.Flow.Destination.Port = 0
			}
			before := bad
			if err := exporter.Export(bad); err != nil {
				t.Fatalf("missing tuple must be excluded, not stop collection: %v", err)
			}
			if bad != before {
				t.Fatal("missing tuple was rewritten")
			}
			if err := exporter.Export(exporterTestWindow()); err != nil {
				t.Fatal(err)
			}
			if err := exporter.Close(); err != nil {
				t.Fatal(err)
			}
			if len(sent) != 1 || sent[0].GetLong("src_port") == 0 || sent[0].GetLong("dst_port") == 0 {
				t.Fatal("incomplete tuple was sent or valid successor was lost")
			}
			s := exporter.Snapshot()
			if s.Queued != 1 || s.Written != 1 || s.Failed != 0 || s.Pending != 0 || s.Dropped != 0 || s.SkippedUnmeasured != 0 {
				t.Fatalf("incorrect outcome accounting: %+v", s)
			}
			b, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(b, &fields); err != nil {
				t.Fatal(err)
			}
			if string(fields["skipped_incomplete_tuple"]) != "1" {
				t.Fatalf("missing explicit incomplete-tuple counter: %s", b)
			}
		})
	}
}
