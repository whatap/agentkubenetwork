package tagcount

import (
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/l7"

	"github.com/whatap/golib/lang/pack"
)

func sampleCoverageDrop() l7.Drop {
	return l7.Drop{
		SchemaVersion: l7.SchemaVersion,
		ObservedAt:    time.Date(2026, 9, 16, 1, 0, 0, 321, time.UTC),
		NodeName:      "node", ObserverPID: 42,
		Protocol: l7.ProtocolHTTP1, Source: string(l7.SourceKernelPlaintext),
		Outcome: "drop", Reason: l7.DropResponseTimeout, Count: 3,
	}
}

func TestPackForL7DropKeepsCoverageSeparate(t *testing.T) {
	d := sampleCoverageDrop()
	p, err := PackForL7Drop(d, 3895, 71)
	if err != nil {
		t.Fatal(err)
	}
	if p.Category != CoverageCategory || p.Pcode != 3895 || p.Oid != 71 || p.Time != d.ObservedAt.UnixMilli() {
		t.Fatal("coverage envelope changed")
	}
	if p.Tags.GetString("observer_node") != "node" || p.Tags.GetString("reason") != d.Reason {
		t.Fatal("coverage identity lost")
	}
	if p.Data.GetLong("reported_count") != 3 || p.Data.GetLong("coverage_record_count") != 1 {
		t.Fatal("coverage counts changed")
	}
	for _, key := range []string{"transaction_count", "latency_us", "status_code", "response_count"} {
		if p.Data.Get(key) != nil {
			t.Fatalf("coverage was turned into request data: %s", key)
		}
	}
	if p.Tags.GetString("record_id") == "" {
		t.Fatal("missing coverage record identity")
	}
	again, err := PackForL7Drop(d, 3895, 71)
	if err != nil || again.Tags.GetString("record_id") != p.Tags.GetString("record_id") {
		t.Fatal("record identity is not deterministic")
	}
	d.ObservedAt = d.ObservedAt.Add(time.Nanosecond)
	next, err := PackForL7Drop(d, 3895, 71)
	if err != nil || next.Tags.GetString("record_id") == p.Tags.GetString("record_id") {
		t.Fatal("same-millisecond records collide")
	}
	encoded := pack.ToBytesPack(p)
	roundtrip, ok := pack.ToPack(encoded).(*pack.TagCountPack)
	if !ok {
		t.Fatal("coverage wire type changed")
	}
	if roundtrip.Tags.GetString("record_id") != p.Tags.GetString("record_id") || roundtrip.Data.GetLong("reported_count") != 3 {
		t.Fatal("coverage wire roundtrip changed data")
	}
}
