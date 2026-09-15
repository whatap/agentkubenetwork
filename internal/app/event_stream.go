package app

import (
	"time"

	"github.com/whatap/agentkubenetwork/internal/collector"
	"github.com/whatap/agentkubenetwork/internal/flow"
)

const (
	resolutionRetryInterval = 25 * time.Millisecond
	resolutionGrace         = 250 * time.Millisecond
	maxPendingResolutions   = 1024
)

type timedEvent struct {
	event      collector.Event
	observedAt time.Time
	err        error
}

// The pump owns Read, not the reader's BPF resources. On early exit cancel
// interrupts a blocked Read and joins the pump before the caller closes those
// resources. Readers without the optional interrupt use their Close contract.
func pumpEvents(reader collector.EventReader, maxEvents int, now func() time.Time) (<-chan timedEvent, func()) {
	stream := make(chan timedEvent, 64)
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		defer close(stream)
		for count := 0; maxEvents == 0 || count < maxEvents; count++ {
			select {
			case <-stop:
				return
			default:
			}
			event, err := reader.Read()
			observedAt := time.Time{}
			if err == nil {
				observedAt = now()
				// A reader may reuse its raw ring-buffer record on the next Read.
				event.Payload = append([]byte(nil), event.Payload...)
			}
			select {
			case stream <- timedEvent{event: event, observedAt: observedAt, err: err}:
			case <-stop:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	return stream, func() {
		close(stop)
		select {
		case <-done:
			return
		default:
		}
		if interrupt, ok := reader.(interface{ InterruptRead() error }); ok {
			_ = interrupt.InterruptRead()
		} else {
			_ = reader.Close()
		}
		<-done
	}
}

type pendingResolution struct {
	observation flow.Observation
	deadline    time.Time
	attempts    int
}

type resolutionEvidence struct {
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
	Attempts int    `json:"attempts"`
}

type resolvedObservation struct {
	flow.Observation
	Resolution resolutionEvidence `json:"destinationResolution"`
}

func resolutionRecord(pending pendingResolution, reason string) resolvedObservation {
	status := "unresolved"
	if pending.observation.DestinationResolved != nil {
		status, reason = "resolved", ""
	}
	return resolvedObservation{pending.observation, resolutionEvidence{status, reason, pending.attempts}}
}
