package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/whatap/agentkubenetwork/internal/collector"
	"github.com/whatap/agentkubenetwork/internal/flow"
)

type delayedResolver struct{ ready time.Time }

func (r *delayedResolver) Resolve(_ string, source, _ flow.Endpoint) (flow.Endpoint, string, bool) {
	if source.Port == 41000 && !time.Now().Before(r.ready) {
		return flow.Endpoint{Address: "10.0.0.99", Port: 8080}, "conntrack", true
	}
	return flow.Endpoint{}, "", false
}
func retryEvent() collector.Event {
	return collector.Event{Kind: collector.EventKindConnect, TimestampNS: 123, Family: collector.AddressFamilyIPv4, Protocol: collector.ProtocolTCP, OldState: collector.TCPStateSynSent, NewState: collector.TCPStateEstablished, SourcePort: 41000, DestinationPort: 8080, SourceAddress: [16]byte{10, 0, 0, 1}, DestinationAddress: [16]byte{10, 0, 0, 2}}
}

type waitingReader struct {
	first bool
	stop  chan struct{}
	once  sync.Once
}

func (r *waitingReader) Read() (collector.Event, error) {
	if !r.first {
		r.first = true
		return retryEvent(), nil
	}
	<-r.stop
	return collector.Event{}, io.EOF
}
func (r *waitingReader) Close() error { r.once.Do(func() { close(r.stop) }); return nil }

type signalWriter struct {
	bytes.Buffer
	written chan struct{}
	once    sync.Once
}

func (w *signalWriter) Write(p []byte) (int, error) {
	n, e := w.Buffer.Write(p)
	w.once.Do(func() { close(w.written) })
	return n, e
}

func TestRetryResolvesWithoutAnotherEvent(t *testing.T) {
	reader := &waitingReader{stop: make(chan struct{})}
	output := &signalWriter{written: make(chan struct{})}
	observed := time.Unix(1000, 0).UTC()
	done := make(chan error, 1)
	go func() {
		done <- RunEvents(reader, output, "node", 0, func() time.Time { return observed }, &delayedResolver{ready: time.Now().Add(35 * time.Millisecond)}, nil)
	}()
	select {
	case <-output.written:
	case <-time.After(time.Second):
		reader.Close()
		<-done
		t.Fatal("no timer-triggered output")
	}
	reader.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var got flow.Observation
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &got); err != nil {
		t.Fatal(err)
	}
	if got.DestinationResolved == nil {
		t.Fatal("fresh connection emitted unresolved before retry")
	}
	if got.ObservedAt != observed || got.KernelTimestampNS != 123 {
		t.Fatalf("original timestamps changed: %+v", got)
	}
}

func TestRetryDrainsAtEOFAndMaxEvents(t *testing.T) {
	for _, limit := range []int{0, 1} {
		reader := &fakeEventReader{events: []collector.Event{retryEvent()}}
		var output bytes.Buffer
		err := RunEvents(reader, &output, "node", limit, time.Now, &delayedResolver{ready: time.Now().Add(35 * time.Millisecond)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		var got resolvedObservation
		if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &got); err != nil {
			t.Fatal(err)
		}
		if got.DestinationResolved == nil || got.Resolution.Attempts < 2 {
			t.Fatalf("did not drain pending resolution: %+v", got)
		}
	}
}

func TestRetryBoundsQueueAndReportsExpiryWithoutLosingRecords(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		events := make([]collector.Event, maxPendingResolutions+1)
		for i := range events {
			events[i] = retryEvent()
			events[i].SourcePort += uint16(i)
			events[i].TimestampNS += uint64(i)
		}
		var output bytes.Buffer
		start := time.Now()
		err := RunEvents(&fakeEventReader{events: events}, &output, "node", 0, time.Now, &delayedResolver{ready: start.Add(time.Hour)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if time.Since(start) > time.Second {
			t.Fatal("retry queue did not finish within its bound")
		}
		decoder := json.NewDecoder(&output)
		reasons := map[string]int{}
		seen := map[uint64]bool{}
		for decoder.More() {
			var item resolvedObservation
			if err := decoder.Decode(&item); err != nil {
				t.Fatal(err)
			}
			if seen[item.KernelTimestampNS] || item.DestinationResolved != nil {
				t.Fatal("duplicate or fabricated resolution")
			}
			seen[item.KernelTimestampNS] = true
			reasons[item.Resolution.Reason]++
		}
		if len(seen) != len(events) || reasons["queue_full"] != 1 || reasons["retry_deadline"] != maxPendingResolutions {
			t.Fatalf("records=%d reasons=%v", len(seen), reasons)
		}
	})
}

type brokenOutput struct{}

func (brokenOutput) Write([]byte) (int, error) { return 0, errors.New("writer failed") }

func TestRetryWriterFailureCancelsBlockedReader(t *testing.T) {
	reader := &waitingReader{stop: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- RunEvents(reader, brokenOutput{}, "node", 0, time.Now, &delayedResolver{}, nil) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("writer failure swallowed")
		}
	case <-time.After(time.Second):
		reader.Close()
		<-done
		t.Fatal("writer failure leaked a blocked reader")
	}
}

func TestRetryDoesNotEnrichEarlierSocketAfterTupleReuse(t *testing.T) {
	first, second := retryEvent(), retryEvent()
	second.TimestampNS++
	var output bytes.Buffer
	err := RunEvents(&fakeEventReader{events: []collector.Event{first, second}}, &output, "node", 0, time.Now, &delayedResolver{ready: time.Now().Add(35 * time.Millisecond)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var earlier resolvedObservation
	if err := json.NewDecoder(&output).Decode(&earlier); err != nil {
		t.Fatal(err)
	}
	if earlier.KernelTimestampNS != first.TimestampNS || earlier.DestinationResolved != nil || earlier.Resolution.Reason != "tuple_reused" {
		t.Fatalf("later socket evidence leaked to earlier socket: %+v", earlier)
	}
}
