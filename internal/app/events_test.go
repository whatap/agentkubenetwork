package app

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/collector"
	"github.com/whatap/agentkubenetwork/internal/dns"
	"github.com/whatap/agentkubenetwork/internal/flow"
	"github.com/whatap/agentkubenetwork/internal/l7"
)

type fakeEventReader struct {
	events []collector.Event
	index  int
}

func (reader *fakeEventReader) Read() (collector.Event, error) {
	if reader.index >= len(reader.events) {
		return collector.Event{}, io.EOF
	}
	event := reader.events[reader.index]
	reader.index++
	return event, nil
}

func (reader *fakeEventReader) Close() error { return nil }

func TestRunEventsWritesKernelObservation(t *testing.T) {
	reader := &fakeEventReader{events: []collector.Event{{
		TimestampNS:        123_456,
		Family:             collector.AddressFamilyIPv4,
		Protocol:           collector.ProtocolTCP,
		OldState:           collector.TCPStateSynSent,
		NewState:           collector.TCPStateEstablished,
		SourcePort:         32_000,
		DestinationPort:    8_080,
		SourceAddress:      [16]byte{10, 0, 0, 10},
		DestinationAddress: [16]byte{10, 0, 0, 20},
	}}}
	observedAt := time.Date(2026, 8, 18, 1, 2, 3, 0, time.UTC)
	var output bytes.Buffer

	if err := RunEvents(reader, &output, "worker-a", 1, func() time.Time { return observedAt }, nil, nil); err != nil {
		t.Fatalf("RunEvents returned error: %v", err)
	}

	var observation flow.Observation
	if err := json.NewDecoder(&output).Decode(&observation); err != nil {
		t.Fatalf("decode observation: %v", err)
	}
	if observation.ObservedAt != observedAt || observation.KernelTimestampNS != 123_456 {
		t.Fatalf("unexpected timestamps: %+v", observation)
	}
	if observation.Flow.NodeName != "worker-a" || observation.Flow.Direction != "egress" {
		t.Fatalf("unexpected flow: %+v", observation.Flow)
	}
}

type fakeProcessResolver struct {
	known map[uint32]flow.Process
}

func (resolver *fakeProcessResolver) Lookup(pid uint32) (flow.Process, bool) {
	process, ok := resolver.known[pid]
	return process, ok
}

func TestRunEventsAttachesSocketOwningProcess(t *testing.T) {
	newEvent := func(pid uint32) collector.Event {
		return collector.Event{
			TimestampNS:        1,
			PID:                pid,
			Family:             collector.AddressFamilyIPv4,
			Protocol:           collector.ProtocolTCP,
			OldState:           collector.TCPStateSynSent,
			NewState:           collector.TCPStateEstablished,
			SourcePort:         32_000,
			DestinationPort:    8_080,
			SourceAddress:      [16]byte{10, 0, 0, 10},
			DestinationAddress: [16]byte{10, 0, 0, 20},
		}
	}
	reader := &fakeEventReader{events: []collector.Event{newEvent(4242), newEvent(9), newEvent(0)}}
	processes := &fakeProcessResolver{known: map[uint32]flow.Process{
		4242: {Comm: "python3", Cmdline: "python3 client.py", StartTimeTicks: 77, ContainerID: "abc", Via: "procfs"},
	}}
	observedAt := time.Date(2026, 9, 3, 1, 2, 3, 0, time.UTC)
	var output bytes.Buffer
	if err := RunEvents(reader, &output, "worker-a", 3, func() time.Time { return observedAt }, nil, processes); err != nil {
		t.Fatalf("RunEvents returned error: %v", err)
	}

	decoder := json.NewDecoder(&output)
	var resolved, bare, kernelOnly flow.Observation
	for _, target := range []*flow.Observation{&resolved, &bare, &kernelOnly} {
		if err := decoder.Decode(target); err != nil {
			t.Fatalf("decode observation: %v", err)
		}
	}
	if resolved.Process == nil || resolved.Process.PID != 4242 || resolved.Process.Comm != "python3" ||
		resolved.Process.ContainerID != "abc" || resolved.Process.StartTimeTicks != 77 || resolved.Process.Via != "procfs" {
		t.Fatalf("expected resolved process identity, got %+v", resolved.Process)
	}
	if bare.Process == nil || *bare.Process != (flow.Process{PID: 9}) {
		t.Fatalf("unresolved PID must keep only the kernel PID, got %+v", bare.Process)
	}
	if kernelOnly.Process != nil {
		t.Fatalf("PID 0 must stay unattributed, got %+v", kernelOnly.Process)
	}
}

func TestRunEventsKeepsBarePIDWithoutProcessResolver(t *testing.T) {
	reader := &fakeEventReader{events: []collector.Event{{
		TimestampNS:        1,
		PID:                31,
		Family:             collector.AddressFamilyIPv4,
		Protocol:           collector.ProtocolTCP,
		OldState:           collector.TCPStateSynSent,
		NewState:           collector.TCPStateEstablished,
		SourcePort:         1,
		DestinationPort:    2,
		SourceAddress:      [16]byte{10, 0, 0, 1},
		DestinationAddress: [16]byte{10, 0, 0, 2},
	}}}
	var output bytes.Buffer
	if err := RunEvents(reader, &output, "worker-a", 1, func() time.Time { return time.Unix(1, 0) }, nil, nil); err != nil {
		t.Fatalf("RunEvents returned error: %v", err)
	}
	var raw map[string]any
	if err := json.NewDecoder(&output).Decode(&raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	process, ok := raw["process"].(map[string]any)
	if !ok || process["pid"] != float64(31) || len(process) != 1 {
		t.Fatalf("expected process to carry only pid, got %v", raw["process"])
	}
}

type fakeResolver struct {
	source      flow.Endpoint
	destination flow.Endpoint
	resolved    flow.Endpoint
}

func (resolver *fakeResolver) Resolve(protocol string, source, destination flow.Endpoint) (flow.Endpoint, string, bool) {
	if protocol == "tcp" && source == resolver.source && destination == resolver.destination {
		return resolver.resolved, "conntrack", true
	}
	return flow.Endpoint{}, "", false
}

func TestRunEventsAnnotatesConntrackResolvedDestination(t *testing.T) {
	reader := &fakeEventReader{events: []collector.Event{{
		TimestampNS:        123_456,
		Family:             collector.AddressFamilyIPv4,
		Protocol:           collector.ProtocolTCP,
		OldState:           collector.TCPStateSynSent,
		NewState:           collector.TCPStateEstablished,
		SourcePort:         41_000,
		DestinationPort:    8_080,
		SourceAddress:      [16]byte{10, 131, 1, 173},
		DestinationAddress: [16]byte{172, 30, 181, 224},
	}}}
	resolver := &fakeResolver{
		source:      flow.Endpoint{Address: "10.131.1.173", Port: 41_000},
		destination: flow.Endpoint{Address: "172.30.181.224", Port: 8_080},
		resolved:    flow.Endpoint{Address: "10.128.3.88", Port: 8_080},
	}
	observedAt := time.Date(2026, 9, 2, 1, 2, 3, 0, time.UTC)
	var output bytes.Buffer

	if err := RunEvents(reader, &output, "worker-a", 1, func() time.Time { return observedAt }, resolver, nil); err != nil {
		t.Fatalf("RunEvents returned error: %v", err)
	}

	var observation flow.Observation
	if err := json.NewDecoder(&output).Decode(&observation); err != nil {
		t.Fatalf("decode observation: %v", err)
	}
	expected := &flow.ResolvedEndpoint{Address: "10.128.3.88", Port: 8_080, Via: "conntrack"}
	if observation.DestinationResolved == nil || *observation.DestinationResolved != *expected {
		t.Fatalf("expected resolved destination %+v, got %+v", expected, observation.DestinationResolved)
	}
	if observation.SourceResolved != nil {
		t.Fatalf("source must stay unresolved: %+v", observation.SourceResolved)
	}
}

func TestRunEventsAnnotatesResolvedSourceForReorderedSample(t *testing.T) {
	// TCP samples are canonically ordered, so the NAT-ed VIP may end up on
	// the source side; the resolver must still attach the real endpoint.
	reader := &fakeEventReader{events: []collector.Event{{
		Kind:               collector.EventKindTCPSample,
		TimestampNS:        123_456,
		Family:             collector.AddressFamilyIPv4,
		Protocol:           collector.ProtocolTCP,
		SRTTMicros:         500,
		SourcePort:         41_000,
		DestinationPort:    8_080,
		SourceAddress:      [16]byte{10, 131, 1, 173},
		DestinationAddress: [16]byte{10, 100, 0, 1},
	}}}
	resolver := &fakeResolver{
		source:      flow.Endpoint{Address: "10.131.1.173", Port: 41_000},
		destination: flow.Endpoint{Address: "10.100.0.1", Port: 8_080},
		resolved:    flow.Endpoint{Address: "10.128.3.88", Port: 8_080},
	}
	observedAt := time.Date(2026, 9, 2, 1, 2, 3, 0, time.UTC)
	var output bytes.Buffer

	if err := RunEvents(reader, &output, "worker-a", 1, func() time.Time { return observedAt }, resolver, nil); err != nil {
		t.Fatalf("RunEvents returned error: %v", err)
	}

	var observation flow.Observation
	if err := json.NewDecoder(&output).Decode(&observation); err != nil {
		t.Fatalf("decode observation: %v", err)
	}
	if observation.Flow.Source.Address != "10.100.0.1" {
		t.Fatalf("expected canonical reorder, got %+v", observation.Flow)
	}
	expected := &flow.ResolvedEndpoint{Address: "10.128.3.88", Port: 8_080, Via: "conntrack"}
	if observation.SourceResolved == nil || *observation.SourceResolved != *expected {
		t.Fatalf("expected resolved source %+v, got %+v", expected, observation.SourceResolved)
	}
}

func encodeDNSMessage(id uint16, response bool, rcode uint8, name string, queryType uint16) []byte {
	flags := uint16(0)
	if response {
		flags |= 0x8000
	}
	flags |= uint16(rcode) & 0x000f
	payload := []byte{
		byte(id >> 8), byte(id),
		byte(flags >> 8), byte(flags),
		0, 1,
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

func TestRunEventsCorrelatesDNSTransactions(t *testing.T) {
	client := [16]byte{10, 131, 1, 173}
	server := [16]byte{172, 30, 0, 10}
	reader := &fakeEventReader{events: []collector.Event{
		{
			Kind:               collector.EventKindDNS,
			TimestampNS:        1_000_000,
			Family:             collector.AddressFamilyIPv4,
			Protocol:           collector.ProtocolUDP,
			Direction:          collector.DirectionSend,
			SourcePort:         41_000,
			DestinationPort:    5_353,
			SourceAddress:      client,
			DestinationAddress: server,
			Payload:            encodeDNSMessage(21, false, 0, "sn-target.hermes-sn-live.svc.cluster.local", 1),
		},
		{
			Kind:               collector.EventKindDNS,
			TimestampNS:        2_500_000,
			Family:             collector.AddressFamilyIPv4,
			Protocol:           collector.ProtocolUDP,
			Direction:          collector.DirectionReceive,
			SourcePort:         5_353,
			DestinationPort:    41_000,
			SourceAddress:      server,
			DestinationAddress: client,
			Payload:            encodeDNSMessage(21, true, 0, "sn-target.hermes-sn-live.svc.cluster.local", 1),
		},
	}}
	observedAt := time.Date(2026, 9, 3, 1, 2, 3, 0, time.UTC)
	var output bytes.Buffer

	if err := RunEvents(reader, &output, "worker-a", 2, func() time.Time { return observedAt }, nil, nil); err != nil {
		t.Fatalf("RunEvents returned error: %v", err)
	}

	var transaction dns.Transaction
	if err := json.NewDecoder(&output).Decode(&transaction); err != nil {
		t.Fatalf("decode DNS transaction: %v", err)
	}
	if transaction.SchemaVersion != dns.SchemaVersion || transaction.Outcome != dns.OutcomeResponse {
		t.Fatalf("unexpected transaction: %+v", transaction)
	}
	if transaction.QueryName != "sn-target.hermes-sn-live.svc.cluster.local" || transaction.QueryType != "A" ||
		transaction.ResponseCode != "NOERROR" {
		t.Fatalf("unexpected query fields: %+v", transaction)
	}
	if transaction.Client != (flow.Endpoint{Address: "10.131.1.173", Port: 41_000}) ||
		transaction.Server != (flow.Endpoint{Address: "172.30.0.10", Port: 5_353}) {
		t.Fatalf("unexpected endpoints: %+v", transaction)
	}
	if transaction.LatencyMicros != 1500 {
		t.Fatalf("expected 1500us latency, got %d", transaction.LatencyMicros)
	}
}

func TestRunEventsCorrelatesL7Fragments(t *testing.T) {
	client := [16]byte{10, 0, 0, 10}
	server := [16]byte{10, 0, 0, 20}
	reader := &fakeEventReader{events: []collector.Event{
		{
			Kind:               collector.EventKindL7Fragment,
			Source:             collector.EventSourceKernelPlaintext,
			TimestampNS:        1_000_000,
			Family:             collector.AddressFamilyIPv4,
			Protocol:           collector.ProtocolTCP,
			SourcePort:         32_000,
			DestinationPort:    8_080,
			SourceAddress:      client,
			DestinationAddress: server,
			Payload:            []byte("GET /orders HTTP/1.1\r\n"),
		},
		{
			Kind:               collector.EventKindL7Fragment,
			Source:             collector.EventSourceKernelPlaintext,
			TimestampNS:        6_000_000,
			Family:             collector.AddressFamilyIPv4,
			Protocol:           collector.ProtocolTCP,
			SourcePort:         8_080,
			DestinationPort:    32_000,
			SourceAddress:      server,
			DestinationAddress: client,
			Payload:            []byte("HTTP/1.1 200 OK\r\n"),
		},
	}}
	var output bytes.Buffer
	if err := RunEvents(reader, &output, "worker-a", 2, func() time.Time {
		return time.Date(2026, 8, 27, 1, 2, 3, 0, time.UTC)
	}, nil, nil); err != nil {
		t.Fatalf("RunEvents returned error: %v", err)
	}

	var transaction l7.Transaction
	if err := json.NewDecoder(&output).Decode(&transaction); err != nil {
		t.Fatalf("decode transaction: %v; output=%q", err, output.String())
	}
	if transaction.Protocol != l7.ProtocolHTTP1 || transaction.Method != "GET" || transaction.Path != "/orders" || transaction.StatusCode != 200 || transaction.ResponseLatencyMicros != 5_000 {
		t.Fatalf("unexpected transaction: %+v", transaction)
	}
}

func TestRunEventsEmitsTupleResolutionDropAndContinues(t *testing.T) {
	reader := &fakeEventReader{events: []collector.Event{
		{
			Kind:       collector.EventKindL7CoverageDrop,
			Source:     collector.EventSourceOpenSSL,
			PID:        42,
			DropReason: collector.DropReasonTupleUnresolved,
		},
		{
			Kind:               collector.EventKindConnect,
			TimestampNS:        123_456,
			Family:             collector.AddressFamilyIPv4,
			Protocol:           collector.ProtocolTCP,
			OldState:           collector.TCPStateSynSent,
			NewState:           collector.TCPStateEstablished,
			SourcePort:         32_000,
			DestinationPort:    8_080,
			SourceAddress:      [16]byte{10, 0, 0, 10},
			DestinationAddress: [16]byte{10, 0, 0, 20},
		},
	}}
	observedAt := time.Date(2026, 8, 27, 1, 2, 3, 0, time.UTC)
	var output bytes.Buffer

	if err := RunEvents(reader, &output, "worker-a", 2, func() time.Time { return observedAt }, nil, nil); err != nil {
		t.Fatalf("RunEvents returned error: %v", err)
	}
	decoder := json.NewDecoder(&output)
	var drop l7.Drop
	if err := decoder.Decode(&drop); err != nil {
		t.Fatalf("decode coverage drop: %v; output=%q", err, output.String())
	}
	if drop.Reason != collector.DropReasonTupleUnresolved || drop.Outcome != "drop" || drop.NodeName != "worker-a" || drop.ObserverPID != 42 || drop.Source != string(l7.SourceOpenSSL) {
		t.Fatalf("unexpected coverage drop: %+v", drop)
	}
	var observation flow.Observation
	if err := decoder.Decode(&observation); err != nil {
		t.Fatalf("decode observation after drop: %v; output=%q", err, output.String())
	}
	if observation.Flow.Source.Address != "10.0.0.10" || observation.Flow.Destination.Address != "10.0.0.20" {
		t.Fatalf("reader did not continue after coverage drop: %+v", observation)
	}
}
