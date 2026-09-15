package l7

import (
	"github.com/whatap/agentkubenetwork/internal/flow"
	"golang.org/x/net/http2/hpack"
	"testing"
	"time"
)

func TestReviewHTTP2ContinuationPreservesStartIdentity(t *testing.T) {
	testReviewHTTP2ContinuationIdentity(t, false)
}

func TestReviewHTTP2ContinuationSnapshotsKnownStartIdentity(t *testing.T) {
	testReviewHTTP2ContinuationIdentity(t, true)
}

func testReviewHTTP2ContinuationIdentity(t *testing.T, known bool) {
	t.Helper()
	c := NewCorrelator(Config{})
	client, server := flow.Endpoint{Address: "10.0.0.1", Port: 41000}, flow.Endpoint{Address: "10.0.0.2", Port: 8080}
	headers := http2TestHeadersFrame(t, newHPACKTestEncoder(t), 1, hpack.HeaderField{Name: ":method", Value: "GET"}, hpack.HeaderField{Name: ":path", Value: "/orders"})
	headers[4] = 0
	first := Fragment{ObservedAt: time.Unix(1, 0), KernelTimestampNS: 1_000_000, NodeName: "node", ObserverPID: 42, Source: SourceOpenSSL, SourceEndpoint: client, DestinationEndpoint: server, Payload: append([]byte(http2ClientPreface), headers...)}
	if known {
		first.Process = &flow.Process{PID: 42, ContainerID: "start-container", Cmdline: "private argument"}
		first.SourceResolved = &flow.ResolvedEndpoint{Address: "10.0.0.10", Port: 41000, Via: "start-source"}
		first.DestinationResolved = &flow.ResolvedEndpoint{Address: "10.0.0.20", Port: 8080, Via: "start-destination"}
	}
	if out := c.Process(first); len(out) != 0 {
		t.Fatal(out)
	}
	if known {
		first.Process.ContainerID = "mutated-container"
		first.SourceResolved.Address = "10.0.0.98"
		first.DestinationResolved.Address = "10.0.0.99"
	}
	last := first
	last.KernelTimestampNS = 2_000_000
	last.DestinationResolved = &flow.ResolvedEndpoint{Address: "10.0.0.99", Port: 8080, Via: "conntrack"}
	last.Process = &flow.Process{PID: 42, ContainerID: "later-container"}
	last.SourceResolved = &flow.ResolvedEndpoint{Address: "10.0.0.97", Port: 41000, Via: "later-source"}
	last.Payload = []byte{0, 0, 0, 9, 4, 0, 0, 0, 1}
	if out := c.Process(last); len(out) != 0 {
		t.Fatal(out)
	}
	response := last
	response.KernelTimestampNS = 3_000_000
	response.SourceEndpoint, response.DestinationEndpoint = server, client
	response.Payload = http2TestHeadersFrame(t, newHPACKTestEncoder(t), 1, hpack.HeaderField{Name: ":status", Value: "200"})
	out := c.Process(response)
	if len(out) != 1 || out[0].Transaction == nil {
		t.Fatalf("no response: %+v", out)
	}
	assertHTTP2Transaction(t, out, 1, "GET", "/orders", 200, 2000)
	tx := out[0].Transaction
	if tx.LatencyBoundary != BoundaryResponseHeaders {
		t.Fatalf("changed latency boundary: %s", tx.LatencyBoundary)
	}
	if known {
		if tx.Process == nil || tx.Process.PID != 42 || tx.Process.ContainerID != "start-container" || tx.Process.Cmdline != "" || tx.SourceResolved == nil || *tx.SourceResolved != (flow.ResolvedEndpoint{Address: "10.0.0.10", Port: 41000, Via: "start-source"}) || tx.DestinationResolved == nil || *tx.DestinationResolved != (flow.ResolvedEndpoint{Address: "10.0.0.20", Port: 8080, Via: "start-destination"}) {
			t.Fatalf("request-start snapshot lost: process=%+v source=%+v destination=%+v", tx.Process, tx.SourceResolved, tx.DestinationResolved)
		}
	} else if tx.DestinationResolved != nil || tx.SourceResolved != nil || tx.Process != nil {
		t.Fatalf("request-start unknown identity replaced by CONTINUATION identity: %+v backend=%+v process=%+v", tx, tx.DestinationResolved, tx.Process)
	}
}
