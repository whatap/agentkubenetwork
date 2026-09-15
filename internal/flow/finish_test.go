package flow

import (
	"encoding/json"
	"testing"
	"time"
)

func TestStreamFinishMarksUnfinishedWindowsAndClosesStream(t *testing.T) {
	s, err := NewStream(StreamConfig{WindowSize: 5 * time.Second, AllowedLateness: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)
	for _, offset := range []time.Duration{time.Second, 6 * time.Second} {
		o := enrichedObservation()
		o.ObservedAt = base.Add(offset)
		if err := s.Add(o); err != nil {
			t.Fatal(err)
		}
	}
	finisher, ok := any(s).(interface{ Finish(time.Time) []Window })
	if !ok {
		t.Fatal("stream has no bounded final flush")
	}
	windows := finisher.Finish(base.Add(8 * time.Second))
	if len(windows) != 2 {
		t.Fatalf("final windows=%d", len(windows))
	}
	for i, w := range windows {
		encoded, err := json.Marshal(w)
		if err != nil {
			t.Fatal(err)
		}
		var result struct{ Partial bool }
		if err := json.Unmarshal(encoded, &result); err != nil {
			t.Fatal(err)
		}
		if result.Partial != (i == 1) {
			t.Fatalf("partial flag incorrect: %s", encoded)
		}
	}
	if next := finisher.Finish(base.Add(9 * time.Second)); len(next) != 0 {
		t.Fatal("duplicated final windows")
	}
	o := enrichedObservation()
	o.ObservedAt = base.Add(time.Hour)
	if err := s.Add(o); err == nil {
		t.Fatal("finished stream silently reopened")
	}
}
