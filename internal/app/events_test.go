package app

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/collector"
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

	if err := RunEvents(reader, &output, "worker-a", 1, func() time.Time { return observedAt }); err != nil {
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
	}); err != nil {
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

	if err := RunEvents(reader, &output, "worker-a", 2, func() time.Time { return observedAt }); err != nil {
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
