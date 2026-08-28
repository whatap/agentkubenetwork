package flow

import "testing"

func TestDistributionMergePreservesWeightedMeanAndIsOrderIndependent(t *testing.T) {
	oneSample := Distribution{
		Count:     1,
		SumMicros: 1_000,
		MinMicros: 1_000,
		MaxMicros: 1_000,
	}
	nineSamples := Distribution{
		Count:     9,
		SumMicros: 90_000,
		MinMicros: 10_000,
		MaxMicros: 10_000,
	}

	forward := oneSample.Merge(nineSamples)
	reverse := nineSamples.Merge(oneSample)

	for name, got := range map[string]Distribution{
		"forward": forward,
		"reverse": reverse,
	} {
		t.Run(name, func(t *testing.T) {
			if got.Count != 10 {
				t.Fatalf("Count = %d, want 10", got.Count)
			}
			if got.SumMicros != 91_000 {
				t.Fatalf("SumMicros = %d, want 91000", got.SumMicros)
			}
			if got.MeanMicros() != 9_100 {
				t.Fatalf("MeanMicros = %d, want 9100", got.MeanMicros())
			}
			if got.MinMicros != 1_000 {
				t.Fatalf("MinMicros = %d, want 1000", got.MinMicros)
			}
			if got.MaxMicros != 10_000 {
				t.Fatalf("MaxMicros = %d, want 10000", got.MaxMicros)
			}
		})
	}
}
