package flow

// Distribution stores mergeable timing statistics. Keeping count and sum avoids
// the order-dependent weighted-average bug in the retired npmAgent pipeline.
type Distribution struct {
	Count     uint64 `json:"count"`
	SumMicros uint64 `json:"sumMicros"`
	MinMicros uint64 `json:"minMicros"`
	MaxMicros uint64 `json:"maxMicros"`
}

func (d Distribution) MeanMicros() uint64 {
	if d.Count == 0 {
		return 0
	}
	return d.SumMicros / d.Count
}

func (d Distribution) Merge(other Distribution) Distribution {
	if d.Count == 0 {
		return other
	}
	if other.Count == 0 {
		return d
	}

	merged := Distribution{
		Count:     d.Count + other.Count,
		SumMicros: d.SumMicros + other.SumMicros,
		MinMicros: d.MinMicros,
		MaxMicros: d.MaxMicros,
	}
	if other.MinMicros < merged.MinMicros {
		merged.MinMicros = other.MinMicros
	}
	if other.MaxMicros > merged.MaxMicros {
		merged.MaxMicros = other.MaxMicros
	}
	return merged
}
