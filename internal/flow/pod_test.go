package flow

import (
	"encoding/json"
	"testing"
	"time"
)

func TestPodUIDSeparatesWindows(t *testing.T) {
	a := Observation{ObservedAt: time.Unix(100, 0), BytesTx: 1}
	// Exercise the wire contract so the initial RED is a behavioral failure.
	var observations []Observation
	for _, uid := range []string{"old", "new"} {
		b, _ := json.Marshal(a)
		var raw map[string]any
		_ = json.Unmarshal(b, &raw)
		raw["sourcePod"] = map[string]any{"uid": uid, "namespace": "ns", "name": "pod"}
		raw["observerPod"] = map[string]any{"uid": uid, "namespace": "ns", "name": "pod"}
		b, _ = json.Marshal(raw)
		var o Observation
		if err := json.Unmarshal(b, &o); err != nil {
			t.Fatal(err)
		}
		observations = append(observations, o)
	}
	windows, err := Aggregate(observations, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(windows) != 2 {
		t.Fatalf("UID reuse merged: got %d windows", len(windows))
	}
	b, _ := json.Marshal(windows[0])
	var raw map[string]any
	_ = json.Unmarshal(b, &raw)
	if raw["sourcePod"] == nil || raw["observerPod"] == nil {
		t.Fatalf("lost identity: %s", b)
	}
}
