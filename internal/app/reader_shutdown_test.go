package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/whatap/agentkubenetwork/internal/collector"
)

type shutdownErrorReader struct {
	read    int
	entered chan struct{}
	closed  chan struct{}
	once    sync.Once
	failure error
}

func (r *shutdownErrorReader) Read() (collector.Event, error) {
	r.read++
	if r.read == 1 {
		return retryEvent(), nil
	}
	close(r.entered)
	<-r.closed
	return collector.Event{}, r.failure
}
func (r *shutdownErrorReader) Close() error { r.once.Do(func() { close(r.closed) }); return nil }

func TestCancellationClassifiesReaderCloseErrors(t *testing.T) {
	for _, tc := range []struct {
		name        string
		err         error
		wantFailure bool
	}{
		{"closed", os.ErrClosed, false},
		{"wrapped_closed", fmt.Errorf("epoll wait: %w", os.ErrClosed), false},
		{"other_failure", io.ErrUnexpectedEOF, true},
		{"lookalike_text", errors.New("file already closed"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				r := &shutdownErrorReader{entered: make(chan struct{}), closed: make(chan struct{}), failure: tc.err}
				var out bytes.Buffer
				result := make(chan error, 1)
				go func() {
					result <- RunEventsWithOptions(ctx, r, &out, "node", 0, time.Now, nil, nil, EventOptions{OutputMode: "raw"})
				}()
				<-r.entered
				synctest.Wait()
				cancel()
				synctest.Wait()
				err := <-result
				if tc.wantFailure {
					if !errors.Is(err, tc.err) {
						t.Fatalf("read failure lost: %v", err)
					}
				} else if err != nil {
					t.Fatalf("expected self-initiated close to succeed: %v", err)
				}
				if got := bytes.Count(out.Bytes(), []byte("\n")); got != 1 {
					t.Fatalf("accepted records=%d, want 1", got)
				}
			})
		})
	}
}

func TestUnrequestedReaderCloseRemainsFailure(t *testing.T) {
	r := &shutdownErrorReader{entered: make(chan struct{}), closed: make(chan struct{}), failure: fmt.Errorf("epoll wait: %w", os.ErrClosed)}
	_ = r.Close()
	var out bytes.Buffer
	err := RunEventsWithOptions(context.Background(), r, &out, "node", 0, time.Now, nil, nil, EventOptions{OutputMode: "raw"})
	if !errors.Is(err, os.ErrClosed) {
		t.Fatalf("unrequested close suppressed: %v", err)
	}
}
