package dns

import (
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
)

func encodeMessage(id uint16, response bool, rcode uint8, name string, queryType uint16) []byte {
	flags := uint16(0)
	if response {
		flags |= 0x8000
	}
	flags |= uint16(rcode) & 0x000f
	payload := []byte{
		byte(id >> 8), byte(id),
		byte(flags >> 8), byte(flags),
		0, 1, // qdcount
		0, 0, 0, 0, 0, 0,
	}
	start := 0
	for index := 0; index <= len(name); index++ {
		if index == len(name) || name[index] == '.' {
			payload = append(payload, byte(index-start))
			payload = append(payload, name[start:index]...)
			start = index + 1
		}
	}
	payload = append(payload, 0)
	payload = append(payload, byte(queryType>>8), byte(queryType), 0, 1)
	return payload
}

func TestParseQueryAndResponse(t *testing.T) {
	query, err := Parse(encodeMessage(0x1234, false, 0, "sn-target.hermes-sn-live.svc.cluster.local", 1))
	if err != nil {
		t.Fatalf("parse query: %v", err)
	}
	if query.Response || query.ID != 0x1234 || query.QuestionName != "sn-target.hermes-sn-live.svc.cluster.local" || query.QuestionType != 1 {
		t.Fatalf("unexpected query: %+v", query)
	}

	response, err := Parse(encodeMessage(0x1234, true, 3, "sn-target.hermes-sn-live.svc.cluster.local", 1))
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if !response.Response || response.ResponseCode != 3 {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestParseRejectsMalformedDatagrams(t *testing.T) {
	if _, err := Parse([]byte{0, 1, 2}); err == nil {
		t.Fatal("short datagram must fail")
	}
	compressed := encodeMessage(1, false, 0, "a", 1)
	compressed[12] = 0xc0
	if _, err := Parse(compressed); err == nil {
		t.Fatal("compressed question name must fail")
	}
	truncated := encodeMessage(1, false, 0, "sn-target", 1)
	if _, err := Parse(truncated[:14]); err == nil {
		t.Fatal("truncated name must fail")
	}
}

func TestCorrelatorMatchesResponseAndComputesLatency(t *testing.T) {
	correlator := NewCorrelator(0)
	client := flow.Endpoint{Address: "10.131.1.173", Port: 41000}
	server := flow.Endpoint{Address: "172.30.0.10", Port: 5353}
	base := time.Date(2026, 9, 3, 1, 0, 0, 0, time.UTC)

	out := correlator.Process(Fragment{
		ObservedAt:        base,
		KernelTimestampNS: 1_000_000,
		NodeName:          "worker-a",
		Source:            client,
		Destination:       server,
		Payload:           encodeMessage(7, false, 0, "sn-target.svc", 1),
	})
	if len(out) != 0 {
		t.Fatalf("query must stay pending, got %+v", out)
	}

	out = correlator.Process(Fragment{
		ObservedAt:        base.Add(2 * time.Millisecond),
		KernelTimestampNS: 3_000_000,
		NodeName:          "worker-a",
		Source:            server,
		Destination:       client,
		Payload:           encodeMessage(7, true, 0, "sn-target.svc", 1),
	})
	if len(out) != 1 {
		t.Fatalf("expected one transaction, got %+v", out)
	}
	transaction := out[0]
	if transaction.Outcome != OutcomeResponse || transaction.ResponseCode != "NOERROR" ||
		transaction.QueryName != "sn-target.svc" || transaction.QueryType != "A" {
		t.Fatalf("unexpected transaction: %+v", transaction)
	}
	if transaction.Client != client || transaction.Server != server {
		t.Fatalf("unexpected endpoints: %+v", transaction)
	}
	if transaction.LatencyMicros != 2000 {
		t.Fatalf("expected 2000us latency, got %d", transaction.LatencyMicros)
	}
}

func TestCorrelatorExpiresUnansweredQueries(t *testing.T) {
	correlator := NewCorrelator(time.Second)
	client := flow.Endpoint{Address: "10.0.0.1", Port: 40000}
	server := flow.Endpoint{Address: "172.30.0.10", Port: 53}
	base := time.Date(2026, 9, 3, 1, 0, 0, 0, time.UTC)

	correlator.Process(Fragment{
		ObservedAt:  base,
		NodeName:    "worker-a",
		Source:      client,
		Destination: server,
		Payload:     encodeMessage(9, false, 0, "missing.svc", 28),
	})
	out := correlator.Process(Fragment{
		ObservedAt:  base.Add(2 * time.Second),
		NodeName:    "worker-a",
		Source:      client,
		Destination: server,
		Payload:     encodeMessage(10, false, 0, "other.svc", 1),
	})
	if len(out) != 1 || out[0].Outcome != OutcomeNoResponse || out[0].QueryName != "missing.svc" || out[0].QueryType != "AAAA" {
		t.Fatalf("expected expired query, got %+v", out)
	}

	flushed := correlator.Flush()
	if len(flushed) != 1 || flushed[0].QueryName != "other.svc" {
		t.Fatalf("expected flushed pending query, got %+v", flushed)
	}
}

func TestCorrelatorReportsParseFailures(t *testing.T) {
	correlator := NewCorrelator(0)
	out := correlator.Process(Fragment{
		ObservedAt:  time.Date(2026, 9, 3, 1, 0, 0, 0, time.UTC),
		NodeName:    "worker-a",
		Source:      flow.Endpoint{Address: "10.0.0.1", Port: 40000},
		Destination: flow.Endpoint{Address: "172.30.0.10", Port: 53},
		Payload:     []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0xc0},
	})
	if len(out) != 1 || out[0].Outcome != OutcomeParseError {
		t.Fatalf("expected parse failure transaction, got %+v", out)
	}
}
