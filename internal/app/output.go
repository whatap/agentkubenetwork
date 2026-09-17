package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultOutputQueueCapacity = 4096
	defaultOutputDrainTimeout  = 5 * time.Second
	maxOutputRecordBytes       = 64 << 10
)

// queuedOutput isolates collection from a slow consumer. There is one writer
// goroutine and a bounded queue; overload loses telemetry, never waits for room.
// Loss is emitted in-band as soon as the consumer recovers. A terminal write
// error is returned to the caller, never retried ambiguously as a fresh record.
// The caller owns output. A generic io.Writer cannot be forcibly interrupted;
// Close bounds how long we wait, and a timed-out writer must be closed by its
// owner (network exporters must additionally use socket write deadlines).
type queuedOutput struct {
	output       io.Writer
	queue        chan []byte
	done         chan struct{}
	failed       chan struct{}
	now          func() time.Time
	nodeName     string
	drainTimeout time.Duration
	mu           sync.Mutex
	err          error
	reportedLost uint64 // owned only by the writer goroutine
	totalLost    atomic.Uint64
}

func newQueuedOutput(output io.Writer, nodeName string, now func() time.Time, capacity int, drainTimeout time.Duration) (*queuedOutput, error) {
	if output == nil || now == nil {
		return nil, errors.New("output and wall clock are required")
	}
	if capacity == 0 {
		capacity = defaultOutputQueueCapacity
	}
	if drainTimeout == 0 {
		drainTimeout = defaultOutputDrainTimeout
	}
	if capacity < 0 || drainTimeout < 0 {
		return nil, errors.New("output queue capacity and drain timeout must be positive")
	}
	q := &queuedOutput{output: output, done: make(chan struct{}), failed: make(chan struct{}), now: now, nodeName: nodeName, drainTimeout: drainTimeout}
	// Suppression is below event routing and aggregation, not a replacement
	// for them. Avoid serializing, queueing, or dropping discarded JSONL.
	if output == io.Discard {
		close(q.done)
		return q, nil
	}
	q.queue = make(chan []byte, capacity)
	go q.run()
	return q, nil
}

func (q *queuedOutput) Encode(value any) error {
	if q.output == io.Discard {
		return nil
	}
	select {
	case <-q.failed:
		return q.Err()
	default:
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return err
	}
	if buffer.Len() > maxOutputRecordBytes {
		return fmt.Errorf("output record exceeds %d bytes", maxOutputRecordBytes)
	}
	select {
	case q.queue <- buffer.Bytes():
	default:
		q.totalLost.Add(1)
	}
	return nil
}

func (q *queuedOutput) Err() error     { q.mu.Lock(); defer q.mu.Unlock(); return q.err }
func (q *queuedOutput) fail(err error) { q.mu.Lock(); q.err = err; q.mu.Unlock(); close(q.failed) }

func (q *queuedOutput) write(record []byte) error {
	n, err := q.output.Write(record)
	if err == nil && n != len(record) {
		return io.ErrShortWrite
	}
	return err
}

func (q *queuedOutput) writeLoss() error {
	// Derive delta and total from one atomic snapshot. Independent counters
	// can expose a drop in one field before it appears in the other.
	total := q.totalLost.Load()
	count := total - q.reportedLost
	if count == 0 {
		return nil
	}
	q.reportedLost = total
	record, err := json.Marshal(struct {
		SchemaVersion       string    `json:"schemaVersion"`
		ObservedAt          time.Time `json:"observedAt"`
		NodeName            string    `json:"nodeName"`
		Reason              string    `json:"reason"`
		DroppedRecords      uint64    `json:"droppedRecords"`
		TotalDroppedRecords uint64    `json:"totalDroppedRecords"`
	}{"network.output.drop/v1alpha1", q.now(), q.nodeName, "output_queue_full", count, total})
	if err != nil {
		return err
	}
	return q.write(append(record, '\n'))
}

func (q *queuedOutput) run() {
	defer close(q.done)
	for record := range q.queue {
		if err := q.write(record); err != nil {
			q.fail(err)
			return
		}
		if err := q.writeLoss(); err != nil {
			q.fail(err)
			return
		}
	}
	if err := q.writeLoss(); err != nil {
		q.fail(err)
	}
}

func (q *queuedOutput) Close() error {
	if q.output == io.Discard {
		return nil
	}
	close(q.queue)
	timer := time.NewTimer(q.drainTimeout)
	defer timer.Stop()
	select {
	case <-q.done:
		return q.Err()
	case <-timer.C:
		return fmt.Errorf("output drain timeout: queued=%d dropped=%d; final delivery is unknown", len(q.queue), q.totalLost.Load())
	}
}
