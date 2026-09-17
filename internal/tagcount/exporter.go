package tagcount

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
	"github.com/whatap/golib/lang/pack"
)

const MaxQueueCapacity = 16384

var (
	ErrClosed       = errors.New("tagcount exporter is closed")
	ErrQueueLoss    = errors.New("tagcount queue overflow")
	ErrDrainTimeout = errors.New("tagcount drain timeout; final delivery is unknown")
)

// Sender owns a connection, not an unbounded background queue. Send must honor
// context cancellation; Close must interrupt pending network operations.
type Sender interface {
	Identity() (int64, int32)
	Send(context.Context, *pack.TagCountPack) error
	Close() error
}

type ExporterConfig struct {
	NodeName      string
	QueueCapacity int
	DrainTimeout  time.Duration
}

type Summary struct {
	SchemaVersion          string `json:"schemaVersion"`
	Stage                  string `json:"stage"`
	Queued                 uint64 `json:"queued"`
	Written                uint64 `json:"written"`
	Failed                 uint64 `json:"failed"`
	Dropped                uint64 `json:"dropped"`
	Pending                uint64 `json:"pending"`
	SkippedPartial         uint64 `json:"skipped_partial"`
	SkippedUnmeasured      uint64 `json:"skipped_unmeasured"`
	SkippedIncompleteTuple uint64 `json:"skipped_incomplete_tuple"`
}

type Exporter struct {
	sender     Sender
	config     ExporterConfig
	pcode      int64
	oid        int32
	queue      chan *pack.TagCountPack
	done       chan struct{}
	failed     chan struct{}
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	closing    bool
	err        error
	summary    Summary
	closeOnce  sync.Once
	closeErr   error
	senderOnce sync.Once
}

func NewExporter(sender Sender, config ExporterConfig) (*Exporter, error) {
	if sender == nil || config.QueueCapacity < 1 || config.QueueCapacity > MaxQueueCapacity || config.DrainTimeout <= 0 {
		return nil, errors.New("sender, bounded positive tagcount queue capacity and positive drain timeout are required")
	}
	if len(config.NodeName) < 1 || len(config.NodeName) > 253 {
		return nil, errors.New("tagcount observer node is required (maximum 253 bytes)")
	}
	for _, c := range config.NodeName {
		if c < 33 || c > 126 {
			return nil, errors.New("tagcount observer node must be printable ASCII without whitespace")
		}
	}
	pcode, oid := sender.Identity()
	if pcode <= 0 || oid == 0 {
		return nil, errors.New("tagcount sender identity is invalid")
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &Exporter{sender: sender, config: config, pcode: pcode, oid: oid,
		queue: make(chan *pack.TagCountPack, config.QueueCapacity), done: make(chan struct{}), failed: make(chan struct{}), ctx: ctx, cancel: cancel,
		summary: Summary{SchemaVersion: "network.tagcount.summary/v1alpha1", Stage: "tcp_write"}}
	go e.run()
	return e, nil
}

// Export snapshots a window without waiting for network I/O or queue space.
// Overflow is counted by Dropped and reported as an error by Close, not retried.
func (e *Exporter) Export(w flow.Window) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closing {
		return ErrClosed
	}
	if e.err != nil {
		return e.err
	}
	if w.Flow.NodeName != e.config.NodeName {
		return errors.New("window observer node does not match tagcount exporter")
	}
	p, err := PackForWindow(w, e.pcode, e.oid)
	switch {
	case errors.Is(err, ErrPartialWindow):
		e.summary.SkippedPartial++
		return nil
	case errors.Is(err, ErrNoSamples):
		e.summary.SkippedUnmeasured++
		return nil
	case errors.Is(err, ErrIncompleteTuple):
		e.summary.SkippedIncompleteTuple++
		return nil
	case err != nil:
		return err
	}
	e.enqueueLocked(p)
	return nil
}

func (e *Exporter) Failed() <-chan struct{} { return e.failed }
func (e *Exporter) Err() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.err
}
func (e *Exporter) Dropped() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.summary.Dropped
}
func (e *Exporter) Snapshot() Summary {
	e.mu.Lock()
	defer e.mu.Unlock()
	summary := e.summary
	summary.Pending = summary.Queued - summary.Written - summary.Failed
	return summary
}

func (e *Exporter) fail(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.err == nil {
		e.err = err
		close(e.failed)
	} else {
		e.err = errors.Join(e.err, err)
	}
}

func (e *Exporter) closeSender() {
	e.senderOnce.Do(func() {
		if err := e.sender.Close(); err != nil {
			e.fail(err)
		}
	})
}

func (e *Exporter) run() {
	defer close(e.done)
	defer e.closeSender()
	for p := range e.queue {
		if e.ctx.Err() != nil {
			return
		}
		err := e.sender.Send(e.ctx, p)
		e.mu.Lock()
		if err != nil {
			e.summary.Failed++
		} else {
			e.summary.Written++
		}
		e.mu.Unlock()
		if err != nil {
			e.fail(err)
			return
		}
	}
}

// Close is terminal. A timed-out in-flight packet remains unknown, never
// re-enqueued. The final snapshot distinguishes failed, pending and dropped.
func (e *Exporter) Close() error {
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.closing = true
		close(e.queue)
		e.mu.Unlock()
		defer e.cancel()
		timer := time.NewTimer(e.config.DrainTimeout)
		defer timer.Stop()
		var timeoutErr error
		select {
		case <-e.done:
		case <-timer.C:
			timeoutErr = ErrDrainTimeout
			e.cancel()
			e.closeSender()
		}
		e.closeErr = errors.Join(e.Err(), timeoutErr)
		summary := e.Snapshot()
		if summary.Dropped > 0 {
			e.closeErr = errors.Join(e.closeErr, fmt.Errorf("%w: dropped=%d", ErrQueueLoss, summary.Dropped))
		}
		if summary.Pending > 0 {
			e.closeErr = errors.Join(e.closeErr, fmt.Errorf("tagcount pending windows not confirmed written: %d", summary.Pending))
		}
	})
	return e.closeErr
}
