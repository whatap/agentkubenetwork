package dns

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
)

var safetyBase = time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)

func safetyQuery(id uint16, at time.Time) Fragment {
	return Fragment{
		ObservedAt: at, KernelTimestampNS: 1_000_000, NodeName: "node-a",
		Source:      flow.Endpoint{Address: "10.0.0.1", Port: 40000},
		Destination: flow.Endpoint{Address: "10.0.0.53", Port: 53},
		Payload:     encodeMessage(id, false, 0, "example.test", 1),
	}
}

func requireReason(t *testing.T, tx Transaction, outcome, reason string) {
	t.Helper()
	data, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if tx.Outcome != outcome || fields["reason"] != reason {
		t.Fatalf("want %s/%s, got %s", outcome, reason, data)
	}
	if _, ok := fields["latencyMicros"]; ok {
		t.Fatalf("missing latency must stay omitted: %s", data)
	}
}

func TestCorrelatorFinishDistinguishesCaptureEnd(t *testing.T) {
	c := NewCorrelator(time.Second)
	finisher, ok := any(c).(interface{ Finish(time.Time) []Transaction })
	if !ok {
		t.Fatal("Correlator must expose Finish(now)")
	}
	c.Process(safetyQuery(1, safetyBase))
	c.Process(safetyQuery(2, safetyBase.Add(500*time.Millisecond)))
	got := finisher.Finish(safetyBase.Add(time.Second))
	if len(got) != 2 {
		t.Fatalf("want both queries, got %+v", got)
	}
	if got[0].Outcome != OutcomeNoResponse || !got[0].ObservedAt.Equal(safetyBase) {
		t.Fatalf("aged queries must expire first: %+v", got)
	}
	requireReason(t, got[1], "incomplete", "capture_ended")
	if got := finisher.Finish(safetyBase.Add(time.Hour)); len(got) != 0 {
		t.Fatalf("Finish must drain exactly once: %+v", got)
	}
	c.Process(safetyQuery(3, safetyBase))
	legacy := c.Flush()
	if len(legacy) != 1 || legacy[0].Outcome != OutcomeNoResponse {
		t.Fatalf("Flush must retain legacy force-no-response behavior: %+v", legacy)
	}
}

func TestCorrelatorDefaultCapacity(t *testing.T) {
	c := NewCorrelator(time.Second)
	for i := 0; i < 16384; i++ {
		if got := c.Process(safetyQuery(uint16(i), safetyBase)); len(got) != 0 {
			t.Fatalf("query %d rejected before capacity: %+v", i, got)
		}
	}
	got := c.Process(safetyQuery(16384, safetyBase))
	if len(got) != 1 {
		t.Fatalf("capacity must emit one explicit result, got %+v", got)
	}
	requireReason(t, got[0], "incomplete", "state_capacity")
	// Existing queries must not be silently evicted to admit the newcomer.
	if got := c.Flush(); len(got) != 16384 {
		t.Fatalf("pending count = %d", len(got))
	}
}

func TestCorrelatorConfigCapacityAndDefaults(t *testing.T) {
	for _, config := range []Config{{}, {Timeout: -1, MaxPending: -1}} {
		c := NewCorrelatorWithConfig(config)
		if c.timeout != 5*time.Second || c.maxPending != 16384 {
			t.Fatalf("nonpositive config must default: %+v", c)
		}
	}
	c := NewCorrelatorWithConfig(Config{Timeout: time.Second, MaxPending: 1})
	c.Process(safetyQuery(1, safetyBase))
	got := c.Process(safetyQuery(2, safetyBase.Add(time.Millisecond)))
	if len(got) != 1 {
		t.Fatalf("custom cap did not reject: %+v", got)
	}
	requireReason(t, got[0], "incomplete", "state_capacity")
	// Expiration runs before admission, so an aged entry frees capacity.
	got = c.Process(safetyQuery(3, safetyBase.Add(time.Second)))
	if len(got) != 1 || got[0].Outcome != OutcomeNoResponse {
		t.Fatalf("must expire and then admit: %+v", got)
	}
	got = c.Finish(safetyBase.Add(time.Second))
	if len(got) != 1 {
		t.Fatalf("new query not retained: %+v", got)
	}
	requireReason(t, got[0], "incomplete", "capture_ended")
}

func safetyResponse(query Fragment, at time.Time, timestamp uint64) Fragment {
	message, err := Parse(query.Payload)
	if err != nil {
		panic(err)
	}
	query.ObservedAt, query.KernelTimestampNS = at, timestamp
	query.Source, query.Destination = query.Destination, query.Source
	query.Payload = encodeMessage(message.ID, true, 0, message.QuestionName, message.QuestionType)
	return query
}

func TestCorrelatorIdentitySeparatesQuestionsAndObservers(t *testing.T) {
	c := NewCorrelator(time.Second)
	queries := []Fragment{
		safetyQuery(1, safetyBase), safetyQuery(1, safetyBase),
		safetyQuery(1, safetyBase), safetyQuery(1, safetyBase),
	}
	queries[1].Payload = encodeMessage(1, false, 0, "example.test", 28)
	queries[2].ObserverPID = 42
	queries[3].NodeName = "node-b"
	for i := range queries {
		queries[i].KernelTimestampNS += uint64(i) * 1000
		c.Process(queries[i])
	}
	for i, query := range queries {
		got := c.Process(safetyResponse(query, safetyBase.Add(time.Millisecond), 2_000_000))
		wantLatency := (uint64(2_000_000) - query.KernelTimestampNS) / 1000
		if len(got) != 1 || got[0].LatencyMicros != wantLatency || got[0].ObserverPID != query.ObserverPID || got[0].NodeName != query.NodeName {
			t.Fatalf("distinct query %d lost its identity: %+v", i, got)
		}
	}
	if got := c.Flush(); len(got) != 0 {
		t.Fatalf("matched queries remained: %+v", got)
	}
}

func TestCorrelatorDuplicateAndKeyReuseSafety(t *testing.T) {
	c := NewCorrelatorWithConfig(Config{Timeout: time.Second, MaxPending: 1})
	first := safetyQuery(1, safetyBase)
	c.Process(first)
	retry := first
	retry.ObservedAt = safetyBase.Add(500 * time.Millisecond)
	retry.KernelTimestampNS += 1000
	for i := 0; i < 100; i++ {
		if got := c.Process(retry); len(got) != 0 {
			t.Fatalf("duplicate consumed capacity: %+v", got)
		}
	}
	got := c.Expire(safetyBase.Add(time.Second))
	if len(got) != 1 || !got[0].ObservedAt.Equal(first.ObservedAt) {
		t.Fatalf("duplicates must not replace or postpone first observation: %+v", got)
	}
	// Reusing a fully retired identity must not inherit a stale heap deadline.
	for i := 0; i < 100; i++ {
		q := safetyQuery(1, safetyBase.Add(2*time.Second))
		c.Process(q)
		got := c.Process(safetyResponse(q, q.ObservedAt.Add(time.Millisecond), 2_000_000))
		if len(got) != 1 || got[0].LatencyMicros != 1000 {
			t.Fatalf("response failed: %+v", got)
		}
		if len(c.pending) != 0 || len(c.deadlines) != 0 {
			t.Fatal("matched entry retained in expiration index")
		}
	}
	q := safetyQuery(1, safetyBase.Add(2500*time.Millisecond))
	c.Process(q)
	if got := c.Expire(safetyBase.Add(3 * time.Second)); len(got) != 0 {
		t.Fatalf("old deadline expired new generation: %+v", got)
	}
	if got := c.Finish(q.ObservedAt); len(got) != 1 {
		t.Fatalf("fresh generation lost: %+v", got)
	}
	if len(c.deadlines) != 0 {
		t.Fatal("Finish retained heap state")
	}
}

func TestCorrelatorExpireIdle(t *testing.T) {
	c := NewCorrelator(time.Second)
	expirer, ok := any(c).(interface{ Expire(time.Time) []Transaction })
	if !ok {
		t.Fatal("Correlator must expose idle Expire without another fragment")
	}
	// Arrival order is not assumed to be observation-time order.
	c.Process(safetyQuery(2, safetyBase.Add(500*time.Millisecond)))
	c.Process(safetyQuery(1, safetyBase))
	if got := expirer.Expire(safetyBase.Add(time.Second - time.Nanosecond)); len(got) != 0 {
		t.Fatalf("expired before deadline: %+v", got)
	}
	got := expirer.Expire(safetyBase.Add(time.Second))
	if len(got) != 1 || got[0].Outcome != OutcomeNoResponse || !got[0].ObservedAt.Equal(safetyBase) {
		t.Fatalf("only aged query must expire at deadline: %+v", got)
	}
	got = expirer.Expire(safetyBase.Add(1500 * time.Millisecond))
	if len(got) != 1 || !got[0].ObservedAt.Equal(safetyBase.Add(500*time.Millisecond)) {
		t.Fatalf("fresh query must remain until its deadline: %+v", got)
	}
	if got := expirer.Expire(safetyBase.Add(time.Hour)); len(got) != 0 {
		t.Fatalf("expiry must be idempotent: %+v", got)
	}
}
