package app

import (
	"errors"
	"io"
	"os"
	"sync"
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

// captureProgress separates capture time from downstream processing/retry time.
// Every accepted read pins the watermark until the consumer receives it.
type captureProgress struct {
	mu          sync.Mutex
	now         func() time.Time
	cutoff      time.Time
	ended       bool
	outstanding []time.Time
}

func (p *captureProgress) accept(terminal bool) time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	at := p.now()
	p.outstanding = append(p.outstanding, at)
	if terminal && !p.ended {
		p.cutoff, p.ended = at, true
	}
	return at
}
func (p *captureProgress) consume() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.outstanding[0] = time.Time{}
	p.outstanding = p.outstanding[1:]
}
func (p *captureProgress) finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.ended {
		p.cutoff, p.ended = p.now(), true
	}
}
func (p *captureProgress) time() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ended {
		return p.cutoff
	}
	return p.now()
}
func (p *captureProgress) watermark() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	at := p.cutoff
	if !p.ended {
		at = p.now()
	}
	for _, pending := range p.outstanding {
		if pending.Before(at) {
			at = pending
		}
	}
	return at
}

// The pump owns Read, not the reader's BPF resources. On early exit cancel
// interrupts a blocked Read and joins the pump before the caller closes those
// resources. Readers without the optional interrupt use their Close contract.
func pumpEvents(reader collector.EventReader, maxEvents int, now func() time.Time) (<-chan timedEvent, func() []timedEvent, *captureProgress) {
	stream := make(chan timedEvent, 64)
	progress := &captureProgress{now: now}
	stop, done := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var unsent *timedEvent
	var drained []timedEvent
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
			if errors.Is(err, os.ErrClosed) {
				// InterruptRead closes the ring reader to unblock epoll. Only
				// classify that error as EOF once our own stop was requested.
				// Earlier read failures and unrelated errors remain failures.
				select {
				case <-stop:
					err = io.EOF
				default:
				}
			}
			observedAt := progress.accept(err != nil || (maxEvents > 0 && count+1 == maxEvents))
			if err == nil {
				// A reader may reuse its raw ring-buffer record on the next Read.
				event.Payload = append([]byte(nil), event.Payload...)
			}
			select {
			case stream <- timedEvent{event: event, observedAt: observedAt, err: err}:
			case <-stop:
				unsent = &timedEvent{event: event, observedAt: observedAt, err: err}
				return
			}
			if err != nil {
				return
			}
		}
	}()
	return stream, func() []timedEvent {
		once.Do(func() {
			progress.finish()
			close(stop)
			select {
			case <-done:
			default:
				if interrupt, ok := reader.(interface{ InterruptRead() error }); ok {
					_ = interrupt.InterruptRead()
				} else {
					_ = reader.Close()
				}
				<-done
			}
			for event := range stream {
				drained = append(drained, event)
			}
			if unsent != nil {
				drained = append(drained, *unsent)
			}
		})
		return drained
	}, progress
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
