package collector

import (
	"errors"
	"testing"
)

type failingEventEnricher struct{}

func (failingEventEnricher) enrich(*Event) error {
	return errors.New("fd closed before /proc resolution")
}

func TestEnrichL7EventTurnsTupleResolutionFailureIntoCoverageDrop(t *testing.T) {
	event := Event{
		Kind:      EventKindL7Fragment,
		Source:    EventSourceOpenSSL,
		PID:       42,
		FD:        7,
		Family:    0,
		Payload:   []byte("GET /secret HTTP/1.1\r\n"),
		Direction: DirectionSend,
	}

	resolved := enrichL7Event(event, failingEventEnricher{})
	if resolved.Kind != EventKindL7CoverageDrop || resolved.DropReason != DropReasonTupleUnresolved {
		t.Fatalf("resolved event = %+v, want tuple-unresolved coverage drop", resolved)
	}
	if len(resolved.Payload) != 0 {
		t.Fatalf("coverage drop retained plaintext payload %q", resolved.Payload)
	}
	if resolved.PID != 42 || resolved.Source != EventSourceOpenSSL {
		t.Fatalf("coverage metadata was not preserved: %+v", resolved)
	}
}

func TestKernelDropEventsReportDeltasAndCounterReset(t *testing.T) {
	previous := kernelDropSnapshot{2, 3, 4}
	current := kernelDropSnapshot{5, 3, 1}
	events := kernelDropEvents(previous, current)
	if len(events) != 2 {
		t.Fatalf("events = %+v, want two changed counters", events)
	}
	if events[0].DropReason != DropReasonKernelRingbufReserve || events[0].DropCount != 3 {
		t.Fatalf("reserve event = %+v", events[0])
	}
	if events[1].DropReason != DropReasonKernelPayloadRead || events[1].DropCount != 1 {
		t.Fatalf("reset payload event = %+v", events[1])
	}
}
