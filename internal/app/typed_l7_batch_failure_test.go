package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/l7"
)

func TestL7BatchRetainsAllEvidenceAfterExporterRejection(t *testing.T) {
	at := time.Unix(100, 0)
	want := errors.New("test-only export failure")
	exporter := &recordingTypedExporter{recordingWindowExporter: recordingWindowExporter{failed: make(chan struct{})}, eventErr: want}
	var output bytes.Buffer
	encoder, err := newEventOutput(&output, "node", func() time.Time { return at }, EventOptions{OutputMode: "windows", WindowExporter: exporter})
	if err != nil {
		t.Fatal(err)
	}
	tx := l7.Transaction{SchemaVersion: l7.SchemaVersion, ObservedAt: at}
	drop := l7.Drop{SchemaVersion: l7.SchemaVersion, ObservedAt: at, Outcome: "drop"}
	if err := encodeL7Outputs(encoder, []l7.Output{{Transaction: &tx}, {Drop: &drop}, {Transaction: &tx}}); !errors.Is(err, want) {
		t.Fatalf("error=%v", err)
	}
	if err := encoder.Close(); err != nil && !errors.Is(err, want) {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&output)
	count := 0
	for {
		var value any
		err := decoder.Decode(&value)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		count++
	}
	if count != 3 || len(exporter.http) != 1 || len(exporter.drops) != 0 {
		t.Fatalf("evidence=%d HTTP sends=%d coverage sends=%d", count, len(exporter.http), len(exporter.drops))
	}
}
