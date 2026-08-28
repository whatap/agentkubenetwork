package collector

import (
	"net"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/l7"
)

func TestEventObservationMapsOutboundTCPConnect(t *testing.T) {
	var source [16]byte
	var destination [16]byte
	copy(source[:4], net.ParseIP("10.0.0.10").To4())
	copy(destination[:4], net.ParseIP("10.0.0.20").To4())

	event := Event{
		TimestampNS:        123_456,
		PID:                42,
		Family:             AddressFamilyIPv4,
		Protocol:           ProtocolTCP,
		OldState:           TCPStateSynSent,
		NewState:           TCPStateEstablished,
		SourcePort:         32_000,
		DestinationPort:    8_080,
		SourceAddress:      source,
		DestinationAddress: destination,
	}
	observedAt := time.Date(2026, 8, 18, 0, 0, 1, 0, time.UTC)

	observation, err := event.Observation("worker-a", observedAt)
	if err != nil {
		t.Fatalf("Observation returned error: %v", err)
	}
	if observation.KernelTimestampNS != event.TimestampNS {
		t.Fatalf("KernelTimestampNS = %d, want %d", observation.KernelTimestampNS, event.TimestampNS)
	}
	if observation.Flow.NodeName != "worker-a" || observation.Flow.Protocol != "tcp" || observation.Flow.Direction != "egress" {
		t.Fatalf("unexpected flow identity: %+v", observation.Flow)
	}
	if observation.Flow.Source.Address != "10.0.0.10" || observation.Flow.Source.Port != 32_000 {
		t.Fatalf("unexpected source: %+v", observation.Flow.Source)
	}
	if observation.Flow.Destination.Address != "10.0.0.20" || observation.Flow.Destination.Port != 8_080 {
		t.Fatalf("unexpected destination: %+v", observation.Flow.Destination)
	}
}

func TestEventObservationMapsSRTTSampleWithoutMixingL7Latency(t *testing.T) {
	event := Event{
		Kind:               EventKindTCPSample,
		TimestampNS:        123_456,
		Family:             AddressFamilyIPv4,
		Protocol:           ProtocolTCP,
		SourcePort:         32_000,
		DestinationPort:    8_080,
		SourceAddress:      [16]byte{10, 0, 0, 10},
		DestinationAddress: [16]byte{10, 0, 0, 20},
		SRTTMicros:         1_250,
		RTTVarMicros:       300,
	}

	observation, err := event.Observation("worker-a", time.Date(2026, 8, 27, 1, 2, 3, 0, time.UTC))
	if err != nil {
		t.Fatalf("Observation returned error: %v", err)
	}
	if observation.RTT.Count != 1 || observation.RTT.SumMicros != 1_250 || observation.RTT.MinMicros != 1_250 || observation.RTT.MaxMicros != 1_250 {
		t.Fatalf("unexpected SRTT distribution: %+v", observation.RTT)
	}
	if observation.Jitter.Count != 1 || observation.Jitter.SumMicros != 300 {
		t.Fatalf("unexpected RTT variation distribution: %+v", observation.Jitter)
	}
}

func TestEventObservationNormalizesSRTTConnectionAcrossSendAndReceive(t *testing.T) {
	send := Event{
		Kind:               EventKindTCPSample,
		Direction:          DirectionSend,
		Family:             AddressFamilyIPv4,
		Protocol:           ProtocolTCP,
		SourcePort:         32_000,
		DestinationPort:    8_080,
		SourceAddress:      [16]byte{10, 0, 0, 10},
		DestinationAddress: [16]byte{10, 0, 0, 20},
		SRTTMicros:         1_000,
	}
	receive := send
	receive.Direction = DirectionReceive
	receive.SourcePort, receive.DestinationPort = send.DestinationPort, send.SourcePort
	receive.SourceAddress, receive.DestinationAddress = send.DestinationAddress, send.SourceAddress
	observedAt := time.Date(2026, 8, 27, 1, 2, 3, 0, time.UTC)

	sendObservation, err := send.Observation("worker-a", observedAt)
	if err != nil {
		t.Fatalf("send Observation returned error: %v", err)
	}
	receiveObservation, err := receive.Observation("worker-a", observedAt)
	if err != nil {
		t.Fatalf("receive Observation returned error: %v", err)
	}
	if sendObservation.Flow != receiveObservation.Flow {
		t.Fatalf("SRTT flow split by sampling direction: send=%+v receive=%+v", sendObservation.Flow, receiveObservation.Flow)
	}
	if sendObservation.Flow.Direction != "connection" {
		t.Fatalf("SRTT flow direction = %q, want connection", sendObservation.Flow.Direction)
	}
}

func TestEventL7FragmentPreservesSourceAndDirection(t *testing.T) {
	event := Event{
		Kind:               EventKindL7Fragment,
		Source:             EventSourceOpenSSL,
		Direction:          DirectionReceive,
		TimestampNS:        123_456,
		Family:             AddressFamilyIPv4,
		Protocol:           ProtocolTCP,
		SourcePort:         8_443,
		DestinationPort:    32_000,
		SourceAddress:      [16]byte{10, 0, 0, 20},
		DestinationAddress: [16]byte{10, 0, 0, 10},
		TotalLength:        512,
		Payload:            []byte("HTTP/1.1 200 OK\r\n\r\n"),
	}

	fragment, err := event.L7Fragment("worker-a", time.Date(2026, 8, 27, 1, 2, 3, 0, time.UTC))
	if err != nil {
		t.Fatalf("L7Fragment returned error: %v", err)
	}
	if fragment.Source != l7.SourceOpenSSL || fragment.SourceEndpoint.Address != "10.0.0.20" || fragment.DestinationEndpoint.Address != "10.0.0.10" {
		t.Fatalf("unexpected L7 fragment: %+v", fragment)
	}
	if string(fragment.Payload) != string(event.Payload) {
		t.Fatalf("payload = %q, want %q", fragment.Payload, event.Payload)
	}
	if fragment.TotalLength != 512 {
		t.Fatalf("total length = %d, want 512", fragment.TotalLength)
	}
}
