package bridge

import (
	"encoding/json"
	"github.com/whatap/agentkubenetwork/internal/flow"
	"os"
	"testing"
)

func TestActualCapturedProducerWindowIsAccepted(t *testing.T) {
	data, err := os.ReadFile("testdata/producer-window.json")
	if err != nil {
		t.Fatal(err)
	}
	var w flow.Window
	if err = json.Unmarshal(data, &w); err != nil {
		t.Fatal(err)
	}
	if w.SchemaVersion != flow.SchemaVersion {
		t.Fatal("fixture is not the actual producer schema")
	}
	if _, err = RequestForWindow(w); err != nil {
		t.Fatalf("real producer window rejected: %v", err)
	}
}
