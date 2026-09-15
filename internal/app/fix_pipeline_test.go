package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/whatap/agentkubenetwork/internal/collector"
	"github.com/whatap/agentkubenetwork/internal/dns"
	"github.com/whatap/agentkubenetwork/internal/flow"
)

func TestFixCaptureCutoffPreservesWindows(t *testing.T) {
	for _, limit := range []int{0, 2} {
		for _, lag := range []time.Duration{0, 350 * time.Millisecond} {
			t.Run(fmt.Sprintf("limit=%d/lag=%s", limit, lag), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					sample := retryEvent()
					sample.Kind = collector.EventKindTCPSample
					sample.SRTTMicros = 500
					reader := &fakeEventReader{events: []collector.Event{sample, retryEvent()}}
					resolver := &heldResolver{release: make(chan struct{})}
					start := time.Now()
					go func() { time.Sleep(lag); close(resolver.release) }()
					var output bytes.Buffer
					if err := RunEventsWithOptions(context.Background(), reader, &output, "node", limit, time.Now, resolver, nil, EventOptions{OutputMode: "windows", WindowSize: 100 * time.Millisecond}); err != nil {
						t.Fatal(err)
					}
					decoder := json.NewDecoder(&output)
					count := uint64(0)
					var rtt flow.Distribution
					for decoder.More() {
						var w flow.Window
						if err := decoder.Decode(&w); err != nil {
							t.Fatal(err)
						}
						if w.ObservationCount == 0 || !w.Partial || !w.LastObservedAt.Equal(start) {
							t.Errorf("capture cutoff lost (start=%v): %+v", start, w)
						}
						count += w.ObservationCount
						rtt.Count += w.RTT.Count
						rtt.SumMicros += w.RTT.SumMicros
					}
					if rtt.Count != 1 || rtt.SumMicros != 500 {
						t.Errorf("measured/unknown RTT changed: %+v", rtt)
					}
					if count != 2 {
						t.Errorf("original observations lost: count=%d want=2", count)
					}
				})
			})
		}
	}
}

func TestFixOutputLossSnapshotIsCoherent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var output bytes.Buffer
		snapshot := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once
		q := &queuedOutput{output: &output, queue: make(chan []byte, 1), failed: make(chan struct{}), now: func() time.Time {
			once.Do(func() { close(snapshot); <-release })
			return time.Now()
		}}
		if err := q.Encode(0); err != nil {
			t.Fatal(err)
		} // occupy the queue
		if err := q.Encode(1); err != nil {
			t.Fatal(err)
		} // first drop
		done := make(chan error, 1)
		go func() { done <- q.writeLoss() }()
		<-snapshot
		if err := q.Encode(2); err != nil {
			t.Fatal(err)
		} // concurrent next drop
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if err := q.writeLoss(); err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(&output)
		var sum uint64
		for decoder.More() {
			var loss struct{ DroppedRecords, TotalDroppedRecords uint64 }
			if err := decoder.Decode(&loss); err != nil {
				t.Fatal(err)
			}
			sum += loss.DroppedRecords
			if loss.TotalDroppedRecords != sum {
				t.Errorf("incoherent loss snapshot: delta=%d total=%d cumulative=%d", loss.DroppedRecords, loss.TotalDroppedRecords, sum)
			}
		}
		if sum != 2 {
			t.Errorf("loss accounting lost records: %d", sum)
		}
	})
}

type unexpectedEOFReader struct{ index int }

func (r *unexpectedEOFReader) Close() error { return nil }
func (r *unexpectedEOFReader) Read() (collector.Event, error) {
	r.index++
	if r.index == 1 {
		return retryEvent(), nil
	}
	return collector.Event{}, io.ErrUnexpectedEOF
}
func TestFixCancelRetainsSavedReadError(t *testing.T) {
	for _, broken := range []bool{false, true} {
		t.Run(fmt.Sprint(broken), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var buffer bytes.Buffer
				var writer io.Writer = &buffer
				if broken {
					writer = brokenOutput{}
				}
				ctx, cancel := context.WithCancel(context.Background())
				result := make(chan error, 1)
				go func() {
					result <- RunEventsWithOptions(ctx, &unexpectedEOFReader{}, writer, "node", 0, time.Now, &delayedResolver{ready: time.Now().Add(time.Hour)}, nil, EventOptions{})
				}()
				synctest.Wait()
				cancel()
				synctest.Wait()
				err := <-result
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Errorf("saved read failure suppressed by cancellation: %v", err)
				}
				if broken && (err == nil || !strings.Contains(err.Error(), "writer failed")) {
					t.Errorf("writer failure missing: %v", err)
				}
			})
		})
	}
}

type agedDNSReader struct{ index int }

func (r *agedDNSReader) Close() error { return nil }
func (r *agedDNSReader) Read() (collector.Event, error) {
	r.index++
	switch r.index {
	case 1:
		return dnsQueryEvent(), nil
	case 2:
		time.Sleep(4900 * time.Millisecond)
		return retryEvent(), nil
	default:
		return collector.Event{}, io.EOF
	}
}
func TestFixEOFRetriesDoNotExpireDNS(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var output bytes.Buffer
		if err := RunEvents(&agedDNSReader{}, &output, "node", 0, time.Now, &delayedResolver{ready: time.Now().Add(time.Hour)}, nil); err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(&output)
		seen := false
		for decoder.More() {
			var tx dns.Transaction
			if err := decoder.Decode(&tx); err != nil {
				t.Fatal(err)
			}
			if tx.Outcome == "" {
				continue
			}
			seen = true
			if tx.Outcome != dns.OutcomeIncomplete || tx.Reason != dns.ReasonCaptureEnded {
				t.Errorf("post-capture retry time expired DNS: %+v", tx)
			}
		}
		if !seen {
			t.Fatal("DNS transaction lost")
		}
	})
}

type successfulInterruptedReader struct {
	started    chan struct{}
	release    chan struct{}
	interrupts atomic.Int64
	closes     atomic.Int64
}

func (r *successfulInterruptedReader) Read() (collector.Event, error) {
	close(r.started)
	<-r.release
	return retryEvent(), nil
}
func (r *successfulInterruptedReader) InterruptRead() error {
	r.interrupts.Add(1)
	close(r.release)
	return nil
}
func (r *successfulInterruptedReader) Close() error { r.closes.Add(1); return nil }
func TestFixPumpStopIsIdempotentAndJoinsSuccessfulRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := &successfulInterruptedReader{started: make(chan struct{}), release: make(chan struct{})}
		stream, stop, _ := pumpEvents(r, 0, time.Now)
		<-r.started
		accepted := stop()
		again := stop()
		if len(accepted) != 1 || len(again) != 1 || accepted[0].event.TimestampNS != 123 || accepted[0].err != nil {
			t.Fatalf("successful in-flight Read lost: %+v / %+v", accepted, again)
		}
		if _, ok := <-stream; ok {
			t.Fatal("pump not joined/drained")
		}
		if r.interrupts.Load() != 1 || r.closes.Load() != 0 {
			t.Fatalf("reader ownership/idempotency violated: interrupts=%d closes=%d", r.interrupts.Load(), r.closes.Load())
		}
	})
}

type completedPumpReader struct {
	fakeEventReader
	closes int
}

func (r *completedPumpReader) Close() error { r.closes++; return nil }
func TestFixPumpCompletedReadNeedsNoInterrupt(t *testing.T) {
	for _, limit := range []int{0, 1} {
		synctest.Test(t, func(t *testing.T) {
			r := &completedPumpReader{fakeEventReader: fakeEventReader{events: []collector.Event{retryEvent()}}}
			stream, stop, _ := pumpEvents(r, limit, time.Now)
			for range stream {
			}
			synctest.Wait()
			if len(stop()) != 0 || len(stop()) != 0 || r.closes != 0 {
				t.Fatalf("completed pump closed reader resources: closes=%d", r.closes)
			}
		})
	}
}

type uniqueAcceptedReader struct{ count atomic.Int64 }

func (r *uniqueAcceptedReader) Close() error { return nil }
func (r *uniqueAcceptedReader) Read() (collector.Event, error) {
	n := r.count.Add(1)
	e := retryEvent()
	e.TimestampNS = uint64(n)
	return e, nil
}

type heldResolver struct {
	once    sync.Once
	release chan struct{}
}

func (r *heldResolver) Resolve(string, flow.Endpoint, flow.Endpoint) (flow.Endpoint, string, bool) {
	r.once.Do(func() { <-r.release })
	return flow.Endpoint{}, "", false
}

func TestFixCancelDrainsAcceptedPumpEvents(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reader := &uniqueAcceptedReader{}
		resolver := &heldResolver{release: make(chan struct{})}
		var output bytes.Buffer
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			result <- RunEventsWithOptions(ctx, reader, &output, "node", 0, time.Now, resolver, nil, EventOptions{})
		}()
		synctest.Wait()
		accepted := reader.count.Load()
		if accepted != 66 {
			t.Fatalf("need consumer + 64 queued + in-flight: got %d", accepted)
		}
		cancel()
		close(resolver.release)
		synctest.Wait()
		if err := <-result; err != nil {
			t.Fatal(err)
		}
		var count int64
		seen := map[uint64]bool{}
		decoder := json.NewDecoder(&output)
		for decoder.More() {
			var record resolvedObservation
			if err := decoder.Decode(&record); err != nil {
				t.Fatal(err)
			}
			if record.ObservedAt.IsZero() || record.Resolution.Status != "unresolved" {
				t.Fatalf("invalid retained record: %+v", record)
			}
			if seen[record.KernelTimestampNS] {
				t.Fatalf("duplicate accepted event %d", record.KernelTimestampNS)
			}
			seen[record.KernelTimestampNS] = true
			count++
		}
		if count != reader.count.Load() {
			t.Fatalf("accepted events silently discarded: output=%d read=%d initiallyAccepted=%d", count, reader.count.Load(), accepted)
		}
	})
}
