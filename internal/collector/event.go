package collector

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
	"github.com/whatap/agentkubenetwork/internal/l7"
)

const (
	AddressFamilyIPv4 uint16 = 2
	AddressFamilyIPv6 uint16 = 10
	ProtocolTCP       uint16 = 6

	TCPStateEstablished uint32 = 1
	TCPStateSynSent     uint32 = 2
	TCPStateSynRecv     uint32 = 3

	EventKindConnect        uint8 = 1
	EventKindTCPSample      uint8 = 2
	EventKindL7Fragment     uint8 = 3
	EventKindL7CoverageDrop uint8 = 4

	EventSourceKernelPlaintext uint8 = 1
	EventSourceOpenSSL         uint8 = 2

	DirectionSend    uint8 = 1
	DirectionReceive uint8 = 2

	DropReasonTupleUnresolved      = "tuple_unresolved"
	DropReasonKernelRingbufReserve = "kernel_ringbuf_reserve_failed"
	DropReasonKernelRingbufOutput  = "kernel_ringbuf_output_failed"
	DropReasonKernelPayloadRead    = "kernel_payload_read_failed"
	kernelDropRingbufReserve       = 0
	kernelDropRingbufOutput        = 1
	kernelDropPayloadRead          = 2
	kernelDropReasonCount          = 3
)

// Event is the userspace representation of one inet_sock_set_state tracepoint
// record. TimestampNS is kernel monotonic time; ObservedAt is supplied by the
// userspace reader so the two clocks remain explicit.
type Event struct {
	Kind               uint8
	Source             uint8
	Direction          uint8
	TimestampNS        uint64
	ConnectionID       uint64
	PID                uint32
	TID                uint32
	Family             uint16
	Protocol           uint16
	OldState           uint32
	NewState           uint32
	SRTTMicros         uint32
	RTTVarMicros       uint32
	TotalLength        uint32
	FD                 int32
	SourcePort         uint16
	DestinationPort    uint16
	SourceAddress      [16]byte
	DestinationAddress [16]byte
	Payload            []byte
	DropReason         string
	DropCount          uint64
}

type kernelDropSnapshot [kernelDropReasonCount]uint64

func kernelDropEvents(previous, current kernelDropSnapshot) []Event {
	reasons := [kernelDropReasonCount]string{
		DropReasonKernelRingbufReserve,
		DropReasonKernelRingbufOutput,
		DropReasonKernelPayloadRead,
	}
	events := make([]Event, 0, kernelDropReasonCount)
	for index, value := range current {
		var delta uint64
		if value >= previous[index] {
			delta = value - previous[index]
		} else {
			delta = value
		}
		if delta == 0 {
			continue
		}
		events = append(events, Event{
			Kind:       EventKindL7CoverageDrop,
			Source:     EventSourceKernelPlaintext,
			DropReason: reasons[index],
			DropCount:  delta,
		})
	}
	return events
}

type eventEnricher interface {
	enrich(*Event) error
}

func enrichL7Event(event Event, enricher eventEnricher) Event {
	if event.Kind != EventKindL7Fragment || event.Family != 0 {
		return event
	}
	if err := enricher.enrich(&event); err == nil {
		return event
	}
	event.Kind = EventKindL7CoverageDrop
	event.DropReason = DropReasonTupleUnresolved
	event.Payload = nil
	event.TotalLength = 0
	return event
}

func (event Event) Observation(nodeName string, observedAt time.Time) (flow.Observation, error) {
	if event.Protocol != ProtocolTCP {
		return flow.Observation{}, fmt.Errorf("unsupported transport protocol %d", event.Protocol)
	}
	if observedAt.IsZero() {
		return flow.Observation{}, errors.New("observation wall time is required")
	}

	sourceAddress, err := formatAddress(event.Family, event.SourceAddress)
	if err != nil {
		return flow.Observation{}, err
	}
	destinationAddress, err := formatAddress(event.Family, event.DestinationAddress)
	if err != nil {
		return flow.Observation{}, err
	}

	source := flow.Endpoint{Address: sourceAddress, Port: event.SourcePort}
	destination := flow.Endpoint{Address: destinationAddress, Port: event.DestinationPort}
	direction := "unknown"
	switch {
	case event.Kind == EventKindTCPSample:
		direction = "connection"
		if endpointLess(destination, source) {
			source, destination = destination, source
		}
	case event.OldState == TCPStateSynSent && event.NewState == TCPStateEstablished:
		direction = "egress"
	case event.OldState == TCPStateSynRecv && event.NewState == TCPStateEstablished:
		direction = "ingress"
	}

	observation := flow.Observation{
		ObservedAt:        observedAt.UTC(),
		KernelTimestampNS: event.TimestampNS,
		Flow: flow.FlowKey{
			NodeName:    nodeName,
			Protocol:    "tcp",
			Direction:   direction,
			Source:      source,
			Destination: destination,
		},
	}
	if event.SRTTMicros > 0 {
		observation.RTT = pointDistribution(uint64(event.SRTTMicros))
	}
	if event.RTTVarMicros > 0 {
		observation.Jitter = pointDistribution(uint64(event.RTTVarMicros))
	}
	return observation, nil
}

func (event Event) L7Fragment(nodeName string, observedAt time.Time) (l7.Fragment, error) {
	if event.Kind != EventKindL7Fragment {
		return l7.Fragment{}, fmt.Errorf("event kind %d is not an L7 fragment", event.Kind)
	}
	if observedAt.IsZero() {
		return l7.Fragment{}, errors.New("observation wall time is required")
	}
	sourceAddress, err := formatAddress(event.Family, event.SourceAddress)
	if err != nil {
		return l7.Fragment{}, err
	}
	destinationAddress, err := formatAddress(event.Family, event.DestinationAddress)
	if err != nil {
		return l7.Fragment{}, err
	}
	return l7.Fragment{
		ObservedAt:          observedAt.UTC(),
		KernelTimestampNS:   event.TimestampNS,
		NodeName:            nodeName,
		ObserverPID:         event.PID,
		Source:              event.l7Source(),
		SourceEndpoint:      flow.Endpoint{Address: sourceAddress, Port: event.SourcePort},
		DestinationEndpoint: flow.Endpoint{Address: destinationAddress, Port: event.DestinationPort},
		TotalLength:         event.TotalLength,
		Payload:             append([]byte(nil), event.Payload...),
	}, nil
}

func (event Event) L7CoverageDrop(nodeName string, observedAt time.Time) (l7.Drop, error) {
	if event.Kind != EventKindL7CoverageDrop {
		return l7.Drop{}, fmt.Errorf("event kind %d is not an L7 coverage drop", event.Kind)
	}
	if observedAt.IsZero() {
		return l7.Drop{}, errors.New("observation wall time is required")
	}
	if event.DropReason == "" {
		return l7.Drop{}, errors.New("L7 coverage drop reason is required")
	}
	count := event.DropCount
	if count == 0 {
		count = 1
	}
	return l7.Drop{
		SchemaVersion: l7.SchemaVersion,
		ObservedAt:    observedAt.UTC(),
		NodeName:      nodeName,
		ObserverPID:   event.PID,
		Source:        string(event.l7Source()),
		Outcome:       "drop",
		Reason:        event.DropReason,
		Count:         count,
	}, nil
}

func (event Event) l7Source() l7.Source {
	if event.Source == EventSourceOpenSSL {
		return l7.SourceOpenSSL
	}
	return l7.SourceKernelPlaintext
}

func pointDistribution(value uint64) flow.Distribution {
	return flow.Distribution{Count: 1, SumMicros: value, MinMicros: value, MaxMicros: value}
}

func endpointLess(left, right flow.Endpoint) bool {
	if left.Address != right.Address {
		return left.Address < right.Address
	}
	return left.Port < right.Port
}

func formatAddress(family uint16, raw [16]byte) (string, error) {
	switch family {
	case AddressFamilyIPv4:
		return net.IP(raw[:4]).String(), nil
	case AddressFamilyIPv6:
		return net.IP(raw[:]).String(), nil
	default:
		return "", fmt.Errorf("unsupported address family %d", family)
	}
}
