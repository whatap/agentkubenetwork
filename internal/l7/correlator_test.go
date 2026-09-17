package l7

import (
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
)

func TestCorrelatorHTTP1RequestResponseHeaders(t *testing.T) {
	correlator := NewCorrelator(Config{})
	client := flow.Endpoint{Address: "10.0.0.10", Port: 32000}
	server := flow.Endpoint{Address: "10.0.0.20", Port: 8080}
	startedAt := time.Date(2026, 8, 27, 1, 2, 3, 0, time.UTC)

	outputs := correlator.Process(Fragment{
		ObservedAt:          startedAt,
		KernelTimestampNS:   1_000_000_000,
		NodeName:            "worker-a",
		Source:              SourceKernelPlaintext,
		SourceEndpoint:      client,
		DestinationEndpoint: server,
		Payload:             []byte("GET /orders/123?debug=true HTTP/1.1\r\nHost: payment\r\n\r\n"),
	})
	if len(outputs) != 0 {
		t.Fatalf("request outputs = %d, want 0", len(outputs))
	}

	outputs = correlator.Process(Fragment{
		ObservedAt:          startedAt.Add(25 * time.Millisecond),
		KernelTimestampNS:   1_025_000_000,
		NodeName:            "worker-a",
		Source:              SourceKernelPlaintext,
		SourceEndpoint:      server,
		DestinationEndpoint: client,
		Payload:             []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"),
	})
	if len(outputs) != 1 || outputs[0].Transaction == nil {
		t.Fatalf("response outputs = %+v, want one transaction", outputs)
	}

	transaction := outputs[0].Transaction
	if transaction.SchemaVersion != SchemaVersion || transaction.Protocol != ProtocolHTTP1 {
		t.Fatalf("unexpected schema/protocol: %+v", transaction)
	}
	if transaction.Flow.Source != client || transaction.Flow.Destination != server {
		t.Fatalf("unexpected logical flow: %+v", transaction.Flow)
	}
	if transaction.Method != "GET" || transaction.Path != "/orders/123" || transaction.StatusCode != 200 {
		t.Fatalf("unexpected HTTP identity: %+v", transaction)
	}
	if transaction.ResponseLatencyMicros != 25_000 || transaction.LatencyBoundary != BoundaryResponseStatus {
		t.Fatalf("unexpected latency: %+v", transaction)
	}
	if transaction.Source != SourceKernelPlaintext {
		t.Fatalf("source = %q, want %q", transaction.Source, SourceKernelPlaintext)
	}
}

func TestCorrelatorHTTP1DropsOverlappingRequestsInsteadOfMispairing(t *testing.T) {
	correlator := NewCorrelator(Config{})
	client := flow.Endpoint{Address: "10.0.0.10", Port: 32000}
	server := flow.Endpoint{Address: "10.0.0.20", Port: 8080}
	fragment := func(timestamp uint64, source, destination flow.Endpoint, payload string) Fragment {
		return Fragment{
			ObservedAt:          time.Unix(0, int64(timestamp)).UTC(),
			KernelTimestampNS:   timestamp,
			NodeName:            "worker-a",
			ObserverPID:         42,
			Source:              SourceKernelPlaintext,
			SourceEndpoint:      source,
			DestinationEndpoint: destination,
			Payload:             []byte(payload),
		}
	}

	if outputs := correlator.Process(fragment(1_000, client, server, "GET /a HTTP/1.1\r\n\r\n")); len(outputs) != 0 {
		t.Fatalf("first request outputs = %+v", outputs)
	}
	outputs := correlator.Process(fragment(2_000, client, server, "GET /b HTTP/1.1\r\n\r\n"))
	if len(outputs) != 1 || outputs[0].Drop == nil || outputs[0].Drop.Reason != DropOverlappingRequest {
		t.Fatalf("overlapping request outputs = %+v", outputs)
	}
	drop := outputs[0].Drop
	if drop.SchemaVersion != SchemaVersion || drop.Outcome != "drop" || drop.NodeName != "worker-a" || drop.ObserverPID != 42 || drop.Protocol != ProtocolHTTP1 || drop.Source != string(SourceKernelPlaintext) {
		t.Fatalf("incomplete drop metadata: %+v", drop)
	}
	if drop.Count != 1 {
		t.Fatalf("drop count = %d, want 1", drop.Count)
	}
	if !drop.ObservedAt.Equal(time.Unix(0, 2_000).UTC()) {
		t.Fatalf("drop observedAt = %s, want %s", drop.ObservedAt, time.Unix(0, 2_000).UTC())
	}
	if outputs := correlator.Process(fragment(3_000, server, client, "HTTP/1.1 200 OK\r\n\r\n")); len(outputs) != 0 {
		t.Fatalf("ambiguous response must not produce a transaction: %+v", outputs)
	}
}

func TestCorrelatorHTTP1DropsPipelinedRequestsInSingleFragment(t *testing.T) {
	correlator := NewCorrelator(Config{})
	client := flow.Endpoint{Address: "10.0.0.10", Port: 32000}
	server := flow.Endpoint{Address: "10.0.0.20", Port: 8080}
	fragment := func(timestamp uint64, source, destination flow.Endpoint, payload string) Fragment {
		return Fragment{
			ObservedAt:          time.Unix(0, int64(timestamp)).UTC(),
			KernelTimestampNS:   timestamp,
			NodeName:            "worker-a",
			ObserverPID:         42,
			Source:              SourceKernelPlaintext,
			SourceEndpoint:      source,
			DestinationEndpoint: destination,
			Payload:             []byte(payload),
		}
	}

	outputs := correlator.Process(fragment(1_000, client, server,
		"GET /a HTTP/1.1\r\nHost: example\r\n\r\nGET /b HTTP/1.1\r\nHost: example\r\n\r\n"))
	if len(outputs) != 1 || outputs[0].Drop == nil || outputs[0].Drop.Reason != DropOverlappingRequest {
		t.Fatalf("pipelined request outputs = %+v", outputs)
	}
	if len(correlator.http1) != 0 || len(correlator.http1Ambiguous) != 1 {
		t.Fatalf("pipelined request state: pending=%d ambiguous=%d", len(correlator.http1), len(correlator.http1Ambiguous))
	}
	if outputs := correlator.Process(fragment(2_000, server, client, "HTTP/1.1 200 OK\r\n\r\n")); len(outputs) != 0 {
		t.Fatalf("ambiguous response outputs = %+v", outputs)
	}
}

func TestCorrelatorHTTP1ExcludesProtocolUpgrade(t *testing.T) {
	correlator := NewCorrelator(Config{})
	client := flow.Endpoint{Address: "10.0.0.10", Port: 32000}
	server := flow.Endpoint{Address: "10.0.0.20", Port: 8080}
	request := Fragment{
		ObservedAt:          time.Unix(0, 1_000).UTC(),
		KernelTimestampNS:   1_000,
		NodeName:            "worker-a",
		Source:              SourceKernelPlaintext,
		SourceEndpoint:      client,
		DestinationEndpoint: server,
		Payload:             []byte("GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"),
	}
	correlator.Process(request)
	response := request
	response.ObservedAt = time.Unix(0, 2_000).UTC()
	response.KernelTimestampNS = 2_000
	response.SourceEndpoint = server
	response.DestinationEndpoint = client
	response.Payload = []byte("HTTP/1.1 101 Switching Protocols\r\n\r\n")

	outputs := correlator.Process(response)
	if len(outputs) != 1 || outputs[0].Drop == nil || outputs[0].Drop.Reason != DropProtocolUpgrade {
		t.Fatalf("upgrade outputs = %+v", outputs)
	}
	if outputs[0].Transaction != nil {
		t.Fatalf("upgrade must not produce latency: %+v", outputs[0].Transaction)
	}
}

func TestCorrelatorHTTP1WaitsForFinalResponseAfter100Continue(t *testing.T) {
	correlator := NewCorrelator(Config{})
	client := flow.Endpoint{Address: "10.0.0.10", Port: 32000}
	server := flow.Endpoint{Address: "10.0.0.20", Port: 8080}
	fragment := func(timestamp uint64, source, destination flow.Endpoint, payload string) Fragment {
		return Fragment{
			ObservedAt:          time.Unix(0, int64(timestamp)).UTC(),
			KernelTimestampNS:   timestamp,
			NodeName:            "worker-a",
			Source:              SourceKernelPlaintext,
			SourceEndpoint:      source,
			DestinationEndpoint: destination,
			Payload:             []byte(payload),
		}
	}

	if outputs := correlator.Process(fragment(1_000_000, client, server, "POST /upload HTTP/1.1\r\nExpect: 100-continue\r\n\r\n")); len(outputs) != 0 {
		t.Fatalf("request outputs = %+v", outputs)
	}
	if outputs := correlator.Process(fragment(2_000_000, server, client, "HTTP/1.1 100 Continue\r\n\r\n")); len(outputs) != 0 {
		t.Fatalf("interim response outputs = %+v, want no completed transaction", outputs)
	}
	outputs := correlator.Process(fragment(6_000_000, server, client, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	if len(outputs) != 1 || outputs[0].Transaction == nil {
		t.Fatalf("final response outputs = %+v, want one transaction", outputs)
	}
	transaction := outputs[0].Transaction
	if transaction.StatusCode != 200 || transaction.ResponseLatencyMicros != 5_000 {
		t.Fatalf("final transaction = %+v", transaction)
	}
}

func TestCorrelatorHTTP1SeparatesSameNodeObservationProcesses(t *testing.T) {
	correlator := NewCorrelator(Config{})
	client := flow.Endpoint{Address: "127.0.0.1", Port: 32000}
	server := flow.Endpoint{Address: "127.0.0.1", Port: 8080}
	request := Fragment{
		ObservedAt:          time.Unix(0, 1_000),
		KernelTimestampNS:   1_000,
		NodeName:            "node-a",
		Source:              SourceKernelPlaintext,
		SourceEndpoint:      client,
		DestinationEndpoint: server,
		Payload:             []byte("GET /same-node HTTP/1.1\r\n"),
	}
	clientRequest := request
	clientRequest.ObserverPID = 100
	serverRequest := request
	serverRequest.ObserverPID = 200
	if output := correlator.Process(clientRequest); len(output) != 0 {
		t.Fatalf("client request output = %+v", output)
	}
	if output := correlator.Process(serverRequest); len(output) != 0 {
		t.Fatalf("server request output = %+v", output)
	}
	clientResponse := Fragment{
		ObservedAt:          time.Unix(0, 6_000),
		KernelTimestampNS:   6_000,
		NodeName:            "node-a",
		ObserverPID:         100,
		Source:              SourceKernelPlaintext,
		SourceEndpoint:      server,
		DestinationEndpoint: client,
		Payload:             []byte("HTTP/1.1 200 OK\r\n"),
	}
	output := correlator.Process(clientResponse)
	if len(output) != 1 || output[0].Transaction == nil || output[0].Transaction.ObserverPID != 100 {
		t.Fatalf("client response output = %+v", output)
	}
}

func TestCorrelatorExpiresPendingHTTP1AsResponseTimeout(t *testing.T) {
	correlator := NewCorrelator(Config{StateTTL: time.Second, SweepEvery: 1})
	client := flow.Endpoint{Address: "10.0.0.10", Port: 32000}
	server := flow.Endpoint{Address: "10.0.0.20", Port: 8080}
	request := Fragment{
		ObservedAt:          time.Unix(1, 0).UTC(),
		KernelTimestampNS:   uint64(time.Second),
		NodeName:            "worker-a",
		ObserverPID:         42,
		Source:              SourceKernelPlaintext,
		SourceEndpoint:      client,
		DestinationEndpoint: server,
		Payload:             []byte("GET /timeout HTTP/1.1\r\n\r\n"),
	}
	if outputs := correlator.Process(request); len(outputs) != 0 {
		t.Fatalf("request outputs = %+v", outputs)
	}

	tick := request
	tick.ObservedAt = time.Unix(3, 0).UTC()
	tick.KernelTimestampNS = uint64(3 * time.Second)
	tick.Payload = []byte("not HTTP")
	outputs := correlator.Process(tick)
	if len(outputs) != 1 || outputs[0].Drop == nil || outputs[0].Drop.Reason != DropResponseTimeout {
		t.Fatalf("expiry outputs = %+v, want response timeout drop", outputs)
	}
	if len(correlator.http1) != 0 {
		t.Fatalf("expired HTTP/1 state retained: %d", len(correlator.http1))
	}
}

func TestCorrelatorAllowsCleanHTTP1AfterAmbiguityExpires(t *testing.T) {
	correlator := NewCorrelator(Config{StateTTL: time.Second, SweepEvery: 1})
	client := flow.Endpoint{Address: "10.0.0.10", Port: 32000}
	server := flow.Endpoint{Address: "10.0.0.20", Port: 8080}
	fragment := func(timestamp time.Duration, source, destination flow.Endpoint, payload string) Fragment {
		return Fragment{
			ObservedAt:          time.Unix(0, int64(timestamp)).UTC(),
			KernelTimestampNS:   uint64(timestamp),
			NodeName:            "worker-a",
			ObserverPID:         42,
			Source:              SourceKernelPlaintext,
			SourceEndpoint:      source,
			DestinationEndpoint: destination,
			Payload:             []byte(payload),
		}
	}

	correlator.Process(fragment(time.Second, client, server, "GET /a HTTP/1.1\r\n\r\n"))
	correlator.Process(fragment(1100*time.Millisecond, client, server, "GET /b HTTP/1.1\r\n\r\n"))
	if len(correlator.http1Ambiguous) != 1 {
		t.Fatalf("ambiguous state = %d, want 1", len(correlator.http1Ambiguous))
	}
	if outputs := correlator.Process(fragment(3*time.Second, client, server, "GET /clean HTTP/1.1\r\n\r\n")); len(outputs) != 0 {
		t.Fatalf("clean request outputs = %+v", outputs)
	}
	outputs := correlator.Process(fragment(3100*time.Millisecond, server, client, "HTTP/1.1 200 OK\r\n\r\n"))
	if len(outputs) != 1 || outputs[0].Transaction == nil || outputs[0].Transaction.Path != "/clean" {
		t.Fatalf("clean response outputs = %+v", outputs)
	}
}

func TestCorrelatorBoundsTrackedHTTP1Connections(t *testing.T) {
	correlator := NewCorrelator(Config{MaxTrackedConnections: 2})
	server := flow.Endpoint{Address: "10.0.0.20", Port: 8080}
	for index := 0; index < 2; index++ {
		outputs := correlator.Process(Fragment{
			ObservedAt:          time.Unix(int64(index+1), 0).UTC(),
			KernelTimestampNS:   uint64(index+1) * uint64(time.Second),
			NodeName:            "worker-a",
			ObserverPID:         uint32(index + 1),
			Source:              SourceKernelPlaintext,
			SourceEndpoint:      flow.Endpoint{Address: "10.0.0.10", Port: uint16(32000 + index)},
			DestinationEndpoint: server,
			Payload:             []byte("GET /pending HTTP/1.1\r\n\r\n"),
		})
		if len(outputs) != 0 {
			t.Fatalf("request %d outputs = %+v", index, outputs)
		}
	}
	outputs := correlator.Process(Fragment{
		ObservedAt:          time.Unix(3, 0).UTC(),
		KernelTimestampNS:   uint64(3 * time.Second),
		NodeName:            "worker-a",
		ObserverPID:         3,
		Source:              SourceKernelPlaintext,
		SourceEndpoint:      flow.Endpoint{Address: "10.0.0.10", Port: 32002},
		DestinationEndpoint: server,
		Payload:             []byte("GET /rejected HTTP/1.1\r\n\r\n"),
	})
	if len(outputs) != 1 || outputs[0].Drop == nil || outputs[0].Drop.Reason != DropStateCapacity {
		t.Fatalf("capacity outputs = %+v", outputs)
	}
	if len(correlator.http1) != 2 {
		t.Fatalf("tracked HTTP/1 connections = %d, want 2", len(correlator.http1))
	}
}
