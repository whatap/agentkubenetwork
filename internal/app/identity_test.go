package app

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/collector"
	"github.com/whatap/agentkubenetwork/internal/flow"
)

type requestIdentityResolver struct{ calls int }

func (r *requestIdentityResolver) Resolve(protocol string, source, destination flow.Endpoint) (flow.Endpoint, string, bool) {
	r.calls++
	address := "10.0.0.90"
	if r.calls > 1 {
		address = "10.0.0.91"
	}
	return flow.Endpoint{Address: address, Port: destination.Port}, "conntrack", true
}

type requestProcessResolver struct{ calls int }

func (r *requestProcessResolver) Lookup(pid uint32) (flow.Process, bool) {
	r.calls++
	return flow.Process{PID: pid, StartTimeTicks: 77, ContainerID: "container-at-request", Cmdline: "must-not-be-serialized", Via: "procfs"}, true
}

func httpIdentityEvents() []collector.Event {
	request := collector.Event{
		Kind: collector.EventKindL7Fragment, Source: collector.EventSourceKernelPlaintext,
		TimestampNS: 1_000_000, PID: 4242, Family: collector.AddressFamilyIPv4, Protocol: collector.ProtocolTCP,
		SourcePort: 41000, DestinationPort: 8080, SourceAddress: [16]byte{10, 0, 0, 1}, DestinationAddress: [16]byte{10, 0, 0, 2},
		Payload: []byte("GET /orders HTTP/1.1\r\n"),
	}
	response := request
	response.TimestampNS = 3_000_000
	response.SourcePort, response.DestinationPort = request.DestinationPort, request.SourcePort
	response.SourceAddress, response.DestinationAddress = request.DestinationAddress, request.SourceAddress
	response.Payload = []byte("HTTP/1.1 200 OK\r\n")
	return []collector.Event{request, response}
}

func TestRunEventsPreservesDNSObservationTimeIdentity(t *testing.T) {
	query := dnsQueryEvent()
	query.TimestampNS = 1_000_000
	response := query
	response.TimestampNS = 2_000_000
	response.SourcePort, response.DestinationPort = query.DestinationPort, query.SourcePort
	response.SourceAddress, response.DestinationAddress = query.DestinationAddress, query.SourceAddress
	response.Payload = append([]byte(nil), query.Payload...)
	response.Payload[2] = 0x81
	resolver, processes := &requestIdentityResolver{}, &requestProcessResolver{}
	var output bytes.Buffer
	if err := RunEvents(&fakeEventReader{events: []collector.Event{query, response}}, &output, "node", 0, time.Now, resolver, processes); err != nil {
		t.Fatal(err)
	}
	var result struct {
		ServerResolved *flow.ResolvedEndpoint `json:"serverResolved"`
		Process        *flow.Process          `json:"process"`
		ObserverPID    uint32                 `json:"observerPid"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &result); err != nil {
		t.Fatal(err)
	}
	if result.ServerResolved == nil || result.ServerResolved.Address != "10.0.0.90" || result.Process == nil || result.Process.ContainerID != "container-at-request" || result.ObserverPID != query.PID {
		t.Fatalf("DNS lost query-time identity: %s", output.String())
	}
	if bytes.Contains(output.Bytes(), []byte("must-not-be-serialized")) {
		t.Fatal("DNS leaked process command line")
	}
}

func TestRunEventsPreservesHTTPObservationTimeIdentity(t *testing.T) {
	resolver, processes := &requestIdentityResolver{}, &requestProcessResolver{}
	var output bytes.Buffer
	if err := RunEvents(&fakeEventReader{events: httpIdentityEvents()}, &output, "node", 0, time.Now, resolver, processes); err != nil {
		t.Fatal(err)
	}
	var record struct {
		DestinationResolved *flow.ResolvedEndpoint `json:"destinationResolved"`
		Process             *flow.Process          `json:"process"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &record); err != nil {
		t.Fatal(err)
	}
	if record.DestinationResolved == nil || record.DestinationResolved.Address != "10.0.0.90" {
		t.Fatalf("HTTP did not retain request-time NAT identity: %s", output.String())
	}
	if record.Process == nil || record.Process.ContainerID != "container-at-request" || record.Process.StartTimeTicks != 77 {
		t.Fatalf("HTTP lost process/container identity: %s", output.String())
	}
	if bytes.Contains(output.Bytes(), []byte("must-not-be-serialized")) {
		t.Fatal("L7 output leaked command line")
	}
}
