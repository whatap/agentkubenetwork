package collector

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestDecodeEventMatchesBPFWireLayout(t *testing.T) {
	payload := [maxPayloadSize]byte{}
	copy(payload[:], "GET / HTTP/1.1\r\n\r\n")
	wire := wireEvent{
		TimestampNS:        123_456,
		ConnectionID:       0xabcdef,
		PID:                42,
		TID:                43,
		OldState:           TCPStateSynSent,
		NewState:           TCPStateEstablished,
		SRTTMicros:         1_250,
		RTTVarMicros:       300,
		TotalLength:        uint32(len("GET / HTTP/1.1\r\n\r\n")),
		FD:                 7,
		Family:             AddressFamilyIPv4,
		Protocol:           ProtocolTCP,
		SourcePort:         32_000,
		DestinationPort:    8_080,
		PayloadLength:      uint16(len("GET / HTTP/1.1\r\n\r\n")),
		Kind:               EventKindL7Fragment,
		Source:             EventSourceOpenSSL,
		Direction:          DirectionSend,
		SourceAddress:      [16]byte{10, 0, 0, 10},
		DestinationAddress: [16]byte{10, 0, 0, 20},
		Payload:            payload,
	}

	var encoded bytes.Buffer
	if err := binary.Write(&encoded, binary.LittleEndian, wire); err != nil {
		t.Fatalf("encode wire event: %v", err)
	}
	if encoded.Len() != bpfEventSize {
		t.Fatalf("encoded size = %d, want %d", encoded.Len(), bpfEventSize)
	}

	event, err := decodeEvent(encoded.Bytes(), binary.LittleEndian)
	if err != nil {
		t.Fatalf("decodeEvent returned error: %v", err)
	}
	if event.TimestampNS != wire.TimestampNS || event.PID != wire.PID {
		t.Fatalf("unexpected identity: %+v", event)
	}
	if event.SourcePort != wire.SourcePort || event.DestinationPort != wire.DestinationPort {
		t.Fatalf("unexpected ports: %+v", event)
	}
	if event.SourceAddress != wire.SourceAddress || event.DestinationAddress != wire.DestinationAddress {
		t.Fatalf("unexpected addresses: %+v", event)
	}
	if event.Kind != wire.Kind || event.Source != wire.Source || event.Direction != wire.Direction {
		t.Fatalf("unexpected event identity: %+v", event)
	}
	if string(event.Payload) != "GET / HTTP/1.1\r\n\r\n" {
		t.Fatalf("unexpected payload: %q", event.Payload)
	}
}
