package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/collector"
	"github.com/whatap/agentkubenetwork/internal/dns"
)

func TestFinishDNSKeepsWholeDrainedBatchAfterExportFailure(t *testing.T) {
	first := dnsQueryEvent()
	second := first
	second.Payload = append([]byte(nil), first.Payload...)
	second.Payload[1] = 2
	reader := &fakeEventReader{events: []collector.Event{first, second}}
	want := errors.New("test-only DNS export failure")
	exporter := &recordingTypedExporter{recordingWindowExporter: recordingWindowExporter{failed: make(chan struct{})}, eventErr: want}
	var output bytes.Buffer
	err := RunEventsWithOptions(context.Background(), reader, &output, "node", 2, time.Now, nil, nil, EventOptions{OutputMode: "windows", WindowExporter: exporter})
	if !errors.Is(err, want) {
		t.Fatalf("missing export failure: %v", err)
	}
	decoder := json.NewDecoder(&output)
	count := 0
	for {
		var record dns.Transaction
		err := decoder.Decode(&record)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if record.SchemaVersion == dns.SchemaVersion {
			count++
			if record.Outcome != dns.OutcomeIncomplete {
				t.Fatal("unfinished query became a response")
			}
		}
	}
	if count != 2 {
		t.Fatalf("drained DNS evidence lost after first rejection: got %d, want 2", count)
	}
	if len(exporter.dns) != 1 {
		t.Fatalf("export retried after first rejection: %d", len(exporter.dns))
	}
}
