package tagcount

import (
	"github.com/whatap/agentkubenetwork/internal/l7"
	"testing"
)

func TestPackForL7RejectsNonfinalResponseOrConnectionStream(t *testing.T) {
	for _, status := range []uint16{100, 199} {
		tx := eventHTTP()
		tx.StatusCode = status
		if _, err := PackForL7(tx, 123, 456); err == nil {
			t.Fatalf("accepted informational status %d as a completed request", status)
		}
	}
	tx := eventHTTP()
	tx.Protocol = l7.ProtocolHTTP2
	tx.LatencyBoundary = l7.BoundaryResponseHeaders
	tx.StreamID = 0
	if _, err := PackForL7(tx, 123, 456); err == nil {
		t.Fatal("accepted connection-level HTTP/2 stream as a request")
	}
}
