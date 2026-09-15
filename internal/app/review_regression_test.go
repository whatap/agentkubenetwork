package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/whatap/agentkubenetwork/internal/dns"
	"github.com/whatap/agentkubenetwork/internal/flow"
	"io"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestReviewCancelPreservesWriterError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reader := newChannelEventReader()
		reader.events <- retryEvent()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		result := make(chan error, 1)
		go func() {
			result <- RunEventsWithOptions(ctx, reader, brokenOutput{}, "node", 0, time.Now, &delayedResolver{ready: time.Now().Add(time.Hour)}, nil, EventOptions{})
		}()
		synctest.Wait()
		cancel()
		synctest.Wait()
		if err := <-result; err == nil || !strings.Contains(err.Error(), "writer failed") {
			t.Fatalf("finalization hid writer failure: %v", err)
		}
	})
}
func TestReviewDNSUsesSuppliedClockDuringIdle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reader := newChannelEventReader()
		reader.events <- dnsQueryEvent()
		var output bytes.Buffer
		now := func() time.Time { return time.Unix(1000, 0).UTC() }
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		result := make(chan error, 1)
		go func() { result <- RunEventsWithOptions(ctx, reader, &output, "node", 0, now, nil, nil, EventOptions{}) }()
		synctest.Wait()
		time.Sleep(50 * time.Millisecond)
		synctest.Wait()
		if output.Len() != 0 {
			t.Errorf("fixed-clock DNS prematurely expired: %s", output.Bytes())
		}
		cancel()
		synctest.Wait()
		if err := <-result; err != nil {
			t.Fatal(err)
		}
		var tx dns.Transaction
		if err := json.NewDecoder(&output).Decode(&tx); err != nil {
			t.Fatal(err)
		}
		if tx.Outcome != dns.OutcomeIncomplete || tx.Reason != "capture_ended" || !tx.ObservedAt.Equal(now()) {
			t.Fatalf("incorrect final DNS: %+v", tx)
		}
	})
}
func TestReviewFixedClockEOFRetryIsBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reader := newChannelEventReader()
		reader.events <- retryEvent()
		close(reader.events)
		var output bytes.Buffer
		now := func() time.Time { return time.Unix(1000, 0).UTC() }
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		result := make(chan error, 1)
		go func() {
			result <- RunEventsWithOptions(ctx, reader, &output, "node", 0, now, &delayedResolver{ready: time.Now().Add(time.Hour)}, nil, EventOptions{})
		}()
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			cancel()
			<-result
			t.Fatal("fixed semantic clock stalled retry deadline")
		}
		var got resolvedObservation
		if err := json.NewDecoder(&output).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.Resolution.Reason != "retry_deadline" || got.Resolution.Attempts < 2 || !got.ObservedAt.Equal(now()) {
			t.Fatalf("incorrect retry: %+v", got)
		}
	})
}
func TestReviewAggregationDropUsesSuppliedClock(t *testing.T) {
	reader := newChannelEventReader()
	reader.events <- retryEvent()
	second := retryEvent()
	second.SourcePort++
	reader.events <- second
	close(reader.events)
	var output bytes.Buffer
	now := func() time.Time { return time.Unix(1000, 0).UTC() }
	if err := RunEventsWithOptions(context.Background(), reader, &output, "node", 0, now, nil, nil, EventOptions{OutputMode: "windows", MaxWindows: 1}); err != nil {
		t.Fatal(err)
	}
	var drop struct {
		Reason     string
		ObservedAt time.Time
	}
	if err := json.NewDecoder(&output).Decode(&drop); err != nil {
		t.Fatal(err)
	}
	if drop.Reason != "window_capacity" || !drop.ObservedAt.Equal(now()) {
		t.Fatalf("incorrect drop clock: %+v", drop)
	}
}

func TestReviewCancelRetainsPending(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reader := newChannelEventReader()
		reader.events <- retryEvent()
		var output bytes.Buffer
		observed := time.Unix(1000, 0).UTC()
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			result <- RunEventsWithOptions(ctx, reader, &output, "node", 0, func() time.Time { return observed }, &delayedResolver{ready: time.Now().Add(time.Hour)}, nil, EventOptions{})
		}()
		synctest.Wait()
		cancel()
		synctest.Wait()
		if err := <-result; err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if output.Len() == 0 {
			t.Fatal("accepted connect event disappeared on cancellation: zero output records")
		}
		var got resolvedObservation
		decoder := json.NewDecoder(&output)
		if err := decoder.Decode(&got); err != nil {
			t.Fatal(err)
		}
		want, err := retryEvent().Observation("node", observed)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got.Observation, want) || got.Resolution.Status != "unresolved" || got.Resolution.Reason != "capture_ended" || got.Resolution.Attempts != 1 {
			t.Fatalf("changed or misclassified pending observation: %+v", got)
		}
		if err := decoder.Decode(&got); err != io.EOF {
			t.Fatalf("expected exactly one record: %v", err)
		}
	})
}
func TestReviewDNSUsesSuppliedClockAtEOF(t *testing.T) {
	reader := newChannelEventReader()
	reader.events <- dnsQueryEvent()
	close(reader.events)
	var output bytes.Buffer
	now := func() time.Time { return time.Unix(1000, 0).UTC() }
	if err := RunEvents(reader, &output, "node", 0, now, nil, nil); err != nil {
		t.Fatal(err)
	}
	var tx dns.Transaction
	if err := json.NewDecoder(&output).Decode(&tx); err != nil {
		t.Fatal(err)
	}
	if tx.Outcome != dns.OutcomeIncomplete {
		t.Fatalf("fresh query at supplied clock misclassified: %+v", tx)
	}
}

func TestReviewWindowsUseSuppliedClock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reader := newChannelEventReader()
		reader.events <- retryEvent()
		var output bytes.Buffer
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		now := func() time.Time { return time.Unix(1000, 0).UTC() }
		go func() {
			result <- RunEventsWithOptions(ctx, reader, &output, "node", 0, now, nil, nil, EventOptions{OutputMode: "windows", WindowSize: 5 * time.Second})
		}()
		synctest.Wait()
		time.Sleep(50 * time.Millisecond)
		synctest.Wait()
		reader.events <- retryEvent()
		synctest.Wait()
		cancel()
		synctest.Wait()
		<-result
		if bytes.Contains(output.Bytes(), []byte("late_observation")) {
			t.Fatalf("same-clock observations falsely finalized/dropped: %s", output.Bytes())
		}
		var window flow.Window
		decoder := json.NewDecoder(&output)
		if err := decoder.Decode(&window); err != nil {
			t.Fatal(err)
		}
		if window.ObservationCount != 2 || !window.Partial || !window.LastObservedAt.Equal(now()) {
			t.Fatalf("wrong count or finish clock: %+v", window)
		}
		if err := decoder.Decode(&window); err != io.EOF {
			t.Fatalf("expected one window: %v", err)
		}
	})
}
