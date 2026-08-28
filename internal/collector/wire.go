package collector

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	maxPayloadSize = 256
	bpfEventSize   = 360
)

// wireEvent mirrors struct flow_event in bpf/flow.bpf.c. Keep the field order
// and explicit reserved word stable; the ring-buffer ABI is versioned by code.
type wireEvent struct {
	TimestampNS        uint64
	ConnectionID       uint64
	PID                uint32
	TID                uint32
	OldState           uint32
	NewState           uint32
	SRTTMicros         uint32
	RTTVarMicros       uint32
	TotalLength        uint32
	FD                 int32
	Family             uint16
	Protocol           uint16
	SourcePort         uint16
	DestinationPort    uint16
	PayloadLength      uint16
	Kind               uint8
	Source             uint8
	Direction          uint8
	Flags              uint8
	Reserved16         uint16
	SourceAddress      [16]byte
	DestinationAddress [16]byte
	Payload            [maxPayloadSize]byte
	Reserved           uint64
}

func decodeEvent(sample []byte, order binary.ByteOrder) (Event, error) {
	if len(sample) != bpfEventSize {
		return Event{}, fmt.Errorf("BPF event size %d, want %d", len(sample), bpfEventSize)
	}

	var wire wireEvent
	if err := binary.Read(bytes.NewReader(sample), order, &wire); err != nil {
		return Event{}, fmt.Errorf("decode BPF event: %w", err)
	}
	if wire.PayloadLength > maxPayloadSize {
		return Event{}, fmt.Errorf("BPF payload length %d exceeds %d", wire.PayloadLength, maxPayloadSize)
	}
	return Event{
		Kind:               wire.Kind,
		Source:             wire.Source,
		Direction:          wire.Direction,
		TimestampNS:        wire.TimestampNS,
		ConnectionID:       wire.ConnectionID,
		PID:                wire.PID,
		TID:                wire.TID,
		Family:             wire.Family,
		Protocol:           wire.Protocol,
		OldState:           wire.OldState,
		NewState:           wire.NewState,
		SRTTMicros:         wire.SRTTMicros,
		RTTVarMicros:       wire.RTTVarMicros,
		TotalLength:        wire.TotalLength,
		FD:                 wire.FD,
		SourcePort:         wire.SourcePort,
		DestinationPort:    wire.DestinationPort,
		SourceAddress:      wire.SourceAddress,
		DestinationAddress: wire.DestinationAddress,
		Payload:            append([]byte(nil), wire.Payload[:wire.PayloadLength]...),
	}, nil
}
