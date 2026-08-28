package flow

import (
	"testing"
	"time"
)

func TestAggregateBuildsDeterministicFiveSecondWindows(t *testing.T) {
	base := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	key := FlowKey{
		NodeName:    "worker-a",
		Protocol:    "tcp",
		Direction:   "egress",
		Source:      Endpoint{Address: "10.0.0.10", Port: 32000},
		Destination: Endpoint{Address: "10.0.0.20", Port: 8080},
	}

	windows, err := Aggregate([]Observation{
		{
			ObservedAt: base.Add(1 * time.Second),
			Flow:       key,
			BytesTx:    100,
			PacketsTx:  2,
			RTT:        Distribution{Count: 1, SumMicros: 1_000, MinMicros: 1_000, MaxMicros: 1_000},
		},
		{
			ObservedAt:      base.Add(4 * time.Second),
			Flow:            key,
			BytesTx:         900,
			PacketsTx:       18,
			Retransmissions: 3,
			RTT:             Distribution{Count: 9, SumMicros: 90_000, MinMicros: 10_000, MaxMicros: 10_000},
		},
		{
			ObservedAt: base.Add(5 * time.Second),
			Flow:       key,
			BytesTx:    50,
			PacketsTx:  1,
			RTT:        Distribution{Count: 1, SumMicros: 2_000, MinMicros: 2_000, MaxMicros: 2_000},
		},
	}, 5*time.Second)
	if err != nil {
		t.Fatalf("Aggregate returned error: %v", err)
	}
	if len(windows) != 2 {
		t.Fatalf("len(windows) = %d, want 2", len(windows))
	}

	first := windows[0]
	if first.SchemaVersion != SchemaVersion {
		t.Fatalf("SchemaVersion = %q, want %q", first.SchemaVersion, SchemaVersion)
	}
	if !first.WindowStart.Equal(base) || !first.WindowEnd.Equal(base.Add(5*time.Second)) {
		t.Fatalf("first window = [%s, %s), want [%s, %s)", first.WindowStart, first.WindowEnd, base, base.Add(5*time.Second))
	}
	if first.BytesTx != 1_000 || first.PacketsTx != 20 || first.Retransmissions != 3 {
		t.Fatalf("first counters = bytes:%d packets:%d retrans:%d", first.BytesTx, first.PacketsTx, first.Retransmissions)
	}
	if first.RTT.Count != 10 || first.RTT.SumMicros != 91_000 || first.RTT.MeanMicros() != 9_100 {
		t.Fatalf("first RTT = %+v, mean=%d", first.RTT, first.RTT.MeanMicros())
	}

	second := windows[1]
	if !second.WindowStart.Equal(base.Add(5*time.Second)) || !second.WindowEnd.Equal(base.Add(10*time.Second)) {
		t.Fatalf("second window = [%s, %s)", second.WindowStart, second.WindowEnd)
	}
	if second.BytesTx != 50 || second.RTT.MeanMicros() != 2_000 {
		t.Fatalf("second window = %+v", second)
	}
}
