package flow

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func enrichedObservation() Observation {
	return Observation{
		ObservedAt:        time.Date(2026, 9, 11, 0, 0, 1, 123456789, time.FixedZone("observer", 9*60*60)),
		KernelTimestampNS: 123456789,
		Flow: FlowKey{
			NodeName: "worker-a", Protocol: "tcp", Direction: "canonical",
			Source:      Endpoint{Address: "10.0.0.10", Port: 8080},
			Destination: Endpoint{Address: "10.0.0.20", Port: 42000},
		},
		SourceResolved:      &ResolvedEndpoint{Address: "10.1.0.10", Port: 8080, Via: "conntrack"},
		DestinationResolved: &ResolvedEndpoint{Address: "10.1.0.20", Port: 42000, Via: "conntrack"},
		Process:             &Process{PID: 42, StartTimeTicks: 99, ContainerID: "container-a", Via: "procfs", Comm: "client", Cmdline: "client --secret=password"},
		BytesTx:             17,
	}
}

func TestAggregatePreservesObserverAndNATIdentity(t *testing.T) {
	observation := enrichedObservation()
	windows, err := Aggregate([]Observation{observation}, 5*time.Second)
	if err != nil || len(windows) != 1 {
		t.Fatalf("Aggregate = %+v, %v", windows, err)
	}
	encoded, err := json.Marshal(windows[0])
	if err != nil {
		t.Fatal(err)
	}
	var got Observation // Existing JSON names remain usable by consumers.
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.SourceResolved, observation.SourceResolved) || !reflect.DeepEqual(got.DestinationResolved, observation.DestinationResolved) {
		t.Fatalf("NAT identity lost: %s", encoded)
	}
	wantProcess := *observation.Process
	wantProcess.Cmdline = ""
	if !reflect.DeepEqual(got.Process, &wantProcess) {
		t.Fatalf("observer identity lost or command line exposed: %s", encoded)
	}
	if got.Flow != observation.Flow {
		t.Fatalf("observer identity must not relabel canonical endpoints: %+v", got.Flow)
	}
	if observation.Process.Cmdline == "" {
		t.Fatal("aggregation modified the input process")
	}
}

func TestAggregateSeparatesConflictingAndMissingIdentity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Observation)
	}{
		{"source unknown", func(o *Observation) { o.SourceResolved = nil }},
		{"source empty", func(o *Observation) { o.SourceResolved = &ResolvedEndpoint{} }},
		{"source address", func(o *Observation) { o.SourceResolved.Address = "10.2.0.1" }},
		{"source port", func(o *Observation) { o.SourceResolved.Port++ }},
		{"source provenance", func(o *Observation) { o.SourceResolved.Via = "other" }},
		{"destination unknown", func(o *Observation) { o.DestinationResolved = nil }},
		{"destination empty", func(o *Observation) { o.DestinationResolved = &ResolvedEndpoint{} }},
		{"destination address", func(o *Observation) { o.DestinationResolved.Address = "10.2.0.2" }},
		{"destination port", func(o *Observation) { o.DestinationResolved.Port++ }},
		{"destination provenance", func(o *Observation) { o.DestinationResolved.Via = "other" }},
		{"observer unknown", func(o *Observation) { o.Process = nil }},
		{"observer empty", func(o *Observation) { o.Process = &Process{} }},
		{"observer pid", func(o *Observation) { o.Process.PID++ }},
		{"observer pid reuse", func(o *Observation) { o.Process.StartTimeTicks++ }},
		{"observer start unknown", func(o *Observation) { o.Process.StartTimeTicks = 0 }},
		{"observer container", func(o *Observation) { o.Process.ContainerID = "container-b" }},
		{"observer container unknown", func(o *Observation) { o.Process.ContainerID = "" }},
		{"observer provenance", func(o *Observation) { o.Process.Via = "other" }},
		{"observer comm", func(o *Observation) { o.Process.Comm = "renamed" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first, second := enrichedObservation(), enrichedObservation()
			tc.change(&second)
			for _, input := range [][]Observation{{first, second}, {second, first}} {
				got, err := Aggregate(input, 5*time.Second)
				if err != nil || len(got) != 2 {
					t.Fatalf("conflicting/unknown enrichment merged: windows=%+v err=%v", got, err)
				}
			}
		})
	}
}

func TestAggregateSortsFullIdentity(t *testing.T) {
	var observations []Observation
	for i := 0; i < 16; i++ {
		o := enrichedObservation()
		if i&1 != 0 {
			o.SourceResolved = nil
		}
		if i&2 != 0 {
			o.DestinationResolved = nil
		}
		if i&4 != 0 {
			o.Process.PID++
		}
		if i&8 != 0 {
			o.Process = nil
		}
		observations = append(observations, o)
	}
	var want string
	for i := 0; i < 30; i++ {
		got, err := Aggregate(observations, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			want = string(encoded)
		}
		if string(encoded) != want {
			t.Fatal("output ordering depends on map/arrival order")
		}
		observations = append(observations[1:], observations[0])
	}
}

func TestAggregateCopiesEnrichmentAndPreservesTimestamp(t *testing.T) {
	o := enrichedObservation()
	original := enrichedObservation()
	older := enrichedObservation()
	older.ObservedAt = o.ObservedAt.Add(-time.Nanosecond)
	got, err := Aggregate([]Observation{o, older}, 5*time.Second)
	if err != nil || len(got) != 1 {
		t.Fatalf("Aggregate = %+v, %v", got, err)
	}
	if !got[0].LastObservedAt.Equal(o.ObservedAt) || got[0].LastObservedAt.Location() != time.UTC {
		t.Fatalf("observation timestamp not retained in UTC: %v", got[0].LastObservedAt)
	}
	o.SourceResolved.Address = "changed"
	o.DestinationResolved.Port = 1
	o.Process.PID = 1
	if *got[0].SourceResolved != *original.SourceResolved || *got[0].DestinationResolved != *original.DestinationResolved || got[0].Process.PID != original.Process.PID {
		t.Fatal("window aliases input pointers")
	}
	got[0].SourceResolved.Port = 1
	got[0].DestinationResolved.Address = "changed"
	got[0].Process.ContainerID = "changed"
	if o.SourceResolved.Port != original.SourceResolved.Port || o.DestinationResolved.Address != original.DestinationResolved.Address || o.Process.ContainerID != original.Process.ContainerID {
		t.Fatal("input aliases output pointers")
	}
	if !o.ObservedAt.Equal(original.ObservedAt) || o.KernelTimestampNS != original.KernelTimestampNS {
		t.Fatal("input timestamps were rewritten")
	}
}

func TestAggregateCountsObservationsNotConnectionsOrRTTSamples(t *testing.T) {
	first, second := enrichedObservation(), enrichedObservation()
	first.RTT = Distribution{Count: 9, SumMicros: 90, MinMicros: 10, MaxMicros: 10}
	second.RTT = Distribution{Count: 1, SumMicros: 30, MinMicros: 30, MaxMicros: 30}
	got, err := Aggregate([]Observation{first, second}, 5*time.Second)
	if err != nil || len(got) != 1 {
		t.Fatalf("Aggregate = %+v, %v", got, err)
	}
	encoded, err := json.Marshal(got[0])
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["observationCount"]) != "2" {
		t.Fatalf("missing observation count, RTT count is not event/connection count: %s", encoded)
	}
	if got[0].RTT != (Distribution{Count: 10, SumMicros: 120, MinMicros: 10, MaxMicros: 30}) {
		t.Fatalf("mergeable RTT changed: %+v", got[0].RTT)
	}
}

func TestAggregateIgnoresCommandLineForIdentity(t *testing.T) {
	first, second := enrichedObservation(), enrichedObservation()
	second.Process.Cmdline = "different sensitive arguments"
	got, err := Aggregate([]Observation{first, second}, 5*time.Second)
	if err != nil || len(got) != 1 || got[0].Process.Cmdline != "" || got[0].BytesTx != 34 {
		t.Fatalf("command line affected aggregation: windows=%+v err=%v", got, err)
	}
}
