package l7

import (
	"github.com/whatap/agentkubenetwork/internal/flow"
	"golang.org/x/net/http2/hpack"
	"testing"
	"time"
)

func TestHTTP2RetainsRequestIdentityWithoutAliasing(t *testing.T) {
	c := NewCorrelator(Config{})
	client, server := flow.Endpoint{Address: "10.0.0.1", Port: 41000}, flow.Endpoint{Address: "10.0.0.2", Port: 8080}
	backend := &flow.ResolvedEndpoint{Address: "10.0.0.90", Port: 8080, Via: "conntrack"}
	process := &flow.Process{PID: 42, StartTimeTicks: 77, ContainerID: "request-container", Cmdline: "private-command"}
	request := Fragment{ObservedAt: time.Unix(1, 0), KernelTimestampNS: 1_000_000, NodeName: "node", ObserverPID: 42, Source: SourceOpenSSL, SourceEndpoint: client, DestinationEndpoint: server, Process: process, DestinationResolved: backend,
		Payload: append([]byte(http2ClientPreface), http2TestHeadersFrame(t, newHPACKTestEncoder(t), 1, hpack.HeaderField{Name: ":method", Value: "GET"}, hpack.HeaderField{Name: ":path", Value: "/orders"})...)}
	if out := c.Process(request); len(out) != 0 {
		t.Fatal(out)
	}
	backend.Address = "10.0.0.99"
	process.ContainerID = "later-container"
	response := request
	response.KernelTimestampNS = 3_000_000
	response.SourceEndpoint, response.DestinationEndpoint = server, client
	response.Payload = http2TestHeadersFrame(t, newHPACKTestEncoder(t), 1, hpack.HeaderField{Name: ":status", Value: "200"})
	out := c.Process(response)
	if len(out) != 1 || out[0].Transaction == nil {
		t.Fatalf("no HTTP2 transaction: %+v", out)
	}
	transaction := out[0].Transaction
	if transaction.DestinationResolved == nil || transaction.DestinationResolved.Address != "10.0.0.90" || transaction.Process == nil || transaction.Process.ContainerID != "request-container" {
		t.Fatalf("lost or mutated request-time identity: %+v", transaction)
	}
	if transaction.Process.Cmdline != "" {
		t.Fatal("retained private command line")
	}
}
