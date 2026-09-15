package flow

import (
	"testing"
	"time"
)

func TestStreamValidatesInputs(t *testing.T) {
	for _, config := range []StreamConfig{
		{},
		{WindowSize: -time.Second},
		{WindowSize: time.Second, AllowedLateness: -time.Nanosecond},
		{WindowSize: time.Second, MaxWindows: -1},
	} {
		if s, err := NewStream(config); err == nil || s != nil {
			t.Errorf("invalid config accepted: %+v, stream=%v err=%v", config, s, err)
		}
	}
	s, err := NewStream(StreamConfig{WindowSize: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Add(Observation{}); err == nil {
		t.Error("zero observation timestamp accepted")
	}
}

func TestStreamHonorsAllowedLateness(t *testing.T) {
	base := time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)
	s, err := NewStream(StreamConfig{WindowSize: 5 * time.Second, AllowedLateness: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	o := enrichedObservation()
	o.ObservedAt = base.Add(time.Second)
	if err := s.Add(o); err != nil {
		t.Fatal(err)
	}
	if got := s.Flush(base.Add(7*time.Second - time.Nanosecond)); len(got) != 0 {
		t.Fatalf("lateness interval was not respected: %+v", got)
	}
	// Out-of-order observations remain valid until their bucket is finalized.
	o.ObservedAt = base.Add(4 * time.Second)
	if err := s.Add(o); err != nil {
		t.Fatal(err)
	}
	if got := s.Flush(base.Add(7 * time.Second)); len(got) != 1 || got[0].ObservationCount != 2 {
		t.Fatalf("lateness boundary flush = %+v", got)
	}
}

func TestStreamWatermarkAdvancesWithoutOutputAndNeverRegresses(t *testing.T) {
	base := time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)
	for _, seed := range []bool{false, true} {
		s, err := NewStream(StreamConfig{WindowSize: 5 * time.Second, AllowedLateness: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		o := enrichedObservation()
		o.ObservedAt = base.Add(time.Second)
		if seed {
			if err := s.Add(o); err != nil {
				t.Fatal(err)
			}
		}
		s.Flush(base.Add(7 * time.Second))
		// Both an emitted identity and one never previously seen must stay closed.
		if err := s.Add(o); err == nil {
			t.Error("finalized bucket recreated")
		}
		o.Process.PID++
		if err := s.Add(o); err == nil {
			t.Error("new identity recreated a finalized bucket")
		}
		s.Flush(base)
		if err := s.Add(o); err == nil {
			t.Error("backward clock reopened finalized bucket")
		}
		o.ObservedAt = base.Add(5 * time.Second)
		if err := s.Add(o); err != nil {
			t.Fatalf("start of next half-open bucket rejected: %v", err)
		}
		if got := s.Flush(base.Add(12 * time.Second)); len(got) != 1 || got[0].ObservationCount != 1 {
			t.Fatalf("late rejections changed window state: %+v", got)
		}
	}
}

func TestStreamBoundsActiveIdentityWindows(t *testing.T) {
	for _, limit := range []int{1, 0} {
		s, err := NewStream(StreamConfig{WindowSize: 5 * time.Second, MaxWindows: limit})
		if err != nil {
			t.Fatal(err)
		}
		want := limit
		if want == 0 {
			want = 16384
		}
		o := enrichedObservation()
		for i := 0; i < want; i++ {
			o.Process.PID = uint32(i)
			if err := s.Add(o); err != nil {
				t.Fatalf("capacity reached at %d: %v", i, err)
			}
		}
		if err := s.Add(o); err != nil {
			t.Fatalf("existing key rejected at capacity: %v", err)
		}
		o.Process = nil
		if err := s.Add(o); err == nil {
			t.Fatal("new identity accepted over capacity")
		}
		o.ObservedAt = o.ObservedAt.Add(5 * time.Second)
		if err := s.Add(o); err == nil {
			t.Fatal("new time bucket accepted over capacity")
		}
		got := s.Flush(o.ObservedAt.UTC().Truncate(5 * time.Second))
		if len(got) != want || got[len(got)-1].ObservationCount != 2 {
			t.Fatalf("capacity evicted or changed accepted records: windows=%d", len(got))
		}
		if err := s.Add(o); err != nil {
			t.Fatalf("flushed capacity not reusable: %v", err)
		}
		if got := s.Flush(o.ObservedAt.Add(5 * time.Second)); len(got) != 1 || got[0].ObservationCount != 1 {
			t.Fatalf("rejected observations leaked into later windows: %+v", got)
		}
	}
}

func TestStreamFlushesOnlyCompletedHalfOpenWindows(t *testing.T) {
	base := time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)
	s, err := NewStream(StreamConfig{WindowSize: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	first, boundary := enrichedObservation(), enrichedObservation()
	first.ObservedAt = base.Add(5*time.Second - time.Nanosecond)
	boundary.ObservedAt = base.Add(5 * time.Second)
	for _, o := range []Observation{first, boundary} {
		if err := s.Add(o); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.Flush(first.ObservedAt); len(got) != 0 {
		t.Fatalf("current bucket emitted early: %+v", got)
	}
	got := s.Flush(boundary.ObservedAt)
	if len(got) != 1 || !got[0].WindowStart.Equal(base) || !got[0].WindowEnd.Equal(boundary.ObservedAt) || !got[0].LastObservedAt.Equal(first.ObservedAt) || got[0].ObservationCount != 1 {
		t.Fatalf("exact boundary flush = %+v", got)
	}
	// A caller's independent timer can flush without any further Add calls.
	got = s.Flush(base.Add(10 * time.Second))
	if len(got) != 1 || !got[0].WindowStart.Equal(boundary.ObservedAt) || got[0].ObservationCount != 1 {
		t.Fatalf("idle flush = %+v", got)
	}
	if got := s.Flush(base.Add(time.Hour)); len(got) != 0 {
		t.Fatalf("empty healthy windows invented: %+v", got)
	}
}
