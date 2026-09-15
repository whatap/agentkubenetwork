package app

import (
	"bytes"
	"context"
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

type channelEventReader struct {
	events chan collector.Event
	stop   chan struct{}
	once   sync.Once
}

func (r *channelEventReader) Read() (collector.Event, error) {
	select {
	case e, ok := <-r.events:
		if !ok {
			return collector.Event{}, io.EOF
		}
		return e, nil
	case <-r.stop:
		return collector.Event{}, io.EOF
	}
}
func (r *channelEventReader) Close() error { r.once.Do(func() { close(r.stop) }); return nil }
func newChannelEventReader() *channelEventReader {
	return &channelEventReader{events: make(chan collector.Event, 16), stop: make(chan struct{})}
}

func TestRunEventsFlushesIdentityWindowsDuringIdle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reader := newChannelEventReader()
		reader.events <- retryEvent()
		var output bytes.Buffer
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		result := make(chan error, 1)
		go func() {
			result <- RunEventsWithOptions(ctx, reader, &output, "node", 0, time.Now, nil, nil, EventOptions{OutputMode: "windows", WindowSize: 100 * time.Millisecond})
		}()
		synctest.Wait()
		time.Sleep(150 * time.Millisecond)
		synctest.Wait()
		var window flow.Window
		if err := json.NewDecoder(bytes.NewReader(output.Bytes())).Decode(&window); err != nil {
			t.Errorf("no idle window before EOF: %v", err)
		} else if window.SchemaVersion != flow.SchemaVersion || window.WindowEnd.IsZero() || window.ObservationCount != 1 {
			t.Errorf("not a real streaming window: %+v", window)
		}
		cancel()
		synctest.Wait()
		if err := <-result; err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
}
