package app

import (
	"bytes"
	"io"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/whatap/agentkubenetwork/internal/collector"
)

type observedEventReader struct {
	count atomic.Int64
	total int64
}

func (r *observedEventReader) Close() error { return nil }
func (r *observedEventReader) Read() (collector.Event, error) {
	if r.count.Load() == r.total {
		return collector.Event{}, io.EOF
	}
	r.count.Add(1)
	return retryEvent(), nil
}

type stalledRecordOutput struct {
	release chan struct{}
	content bytes.Buffer
}

func (w *stalledRecordOutput) Write(p []byte) (int, error) { <-w.release; return w.content.Write(p) }

func TestRunEventsContinuesCaptureWhileOutputStalls(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reader := &observedEventReader{total: 8000}
		output := &stalledRecordOutput{release: make(chan struct{})}
		result := make(chan error, 1)
		go func() { result <- RunEvents(reader, output, "node", 0, time.Now, nil, nil) }()
		synctest.Wait()
		if got := reader.count.Load(); got != reader.total {
			t.Errorf("capture blocked behind output: read=%d want=%d", got, reader.total)
		}
		close(output.release)
		synctest.Wait()
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("pipeline did not shut down")
		}
		if !bytes.Contains(output.content.Bytes(), []byte(`"reason":"output_queue_full"`)) {
			t.Error("output overload was not explicitly reported")
		}
	})
}
