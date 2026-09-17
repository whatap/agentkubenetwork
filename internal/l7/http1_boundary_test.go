package l7

import (
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
)

func TestHTTP1NamesObservedStatusLineBoundary(t *testing.T) {
	c := NewCorrelator(Config{})
	client := flow.Endpoint{Address: "10.1.0.1", Port: 40000}
	server := flow.Endpoint{Address: "10.1.0.2", Port: 8080}
	request := Fragment{ObservedAt: time.Unix(100, 0), KernelTimestampNS: 1_000_000, NodeName: "node-a", Source: SourceKernelPlaintext, SourceEndpoint: client, DestinationEndpoint: server, Payload: []byte("GET /boundary HTTP/1.1\r\n\r\n")}
	if got := c.Process(request); len(got) != 0 {
		t.Fatalf("request outputs: %+v", got)
	}
	response := request
	response.ObservedAt = request.ObservedAt.Add(time.Millisecond)
	response.KernelTimestampNS += 1_000_000
	response.SourceEndpoint, response.DestinationEndpoint = server, client
	response.Payload = []byte("HTTP/1.1 200 OK\r\n") // No headers terminator or body.
	got := c.Process(response)
	if len(got) != 1 || got[0].Transaction == nil {
		t.Fatalf("status-line outputs: %+v", got)
	}
	if got[0].Transaction.LatencyBoundary != "request_to_response_status" {
		t.Fatalf("incomplete headers must not be labelled complete: %q", got[0].Transaction.LatencyBoundary)
	}
}
