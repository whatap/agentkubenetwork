package flow

import (
	"errors"
	"sort"
	"time"
)

const SchemaVersion = "network.flow/v1alpha1"

type Endpoint struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
}

type FlowKey struct {
	NodeName    string   `json:"nodeName"`
	Protocol    string   `json:"protocol"`
	Direction   string   `json:"direction"`
	Source      Endpoint `json:"source"`
	Destination Endpoint `json:"destination"`
}

type Observation struct {
	ObservedAt        time.Time    `json:"observedAt"`
	KernelTimestampNS uint64       `json:"kernelTimestampNs,omitempty"`
	Flow              FlowKey      `json:"flow"`
	BytesTx           uint64       `json:"bytesTx"`
	BytesRx           uint64       `json:"bytesRx"`
	PacketsTx         uint64       `json:"packetsTx"`
	PacketsRx         uint64       `json:"packetsRx"`
	Retransmissions   uint64       `json:"retransmissions"`
	Losses            uint64       `json:"losses"`
	RTT               Distribution `json:"rtt"`
	Jitter            Distribution `json:"jitter"`
}

type Window struct {
	SchemaVersion   string       `json:"schemaVersion"`
	WindowStart     time.Time    `json:"windowStart"`
	WindowEnd       time.Time    `json:"windowEnd"`
	LastObservedAt  time.Time    `json:"lastObservedAt"`
	Flow            FlowKey      `json:"flow"`
	BytesTx         uint64       `json:"bytesTx"`
	BytesRx         uint64       `json:"bytesRx"`
	PacketsTx       uint64       `json:"packetsTx"`
	PacketsRx       uint64       `json:"packetsRx"`
	Retransmissions uint64       `json:"retransmissions"`
	Losses          uint64       `json:"losses"`
	RTT             Distribution `json:"rtt"`
	Jitter          Distribution `json:"jitter"`
}

type aggregateKey struct {
	Start time.Time
	Flow  FlowKey
}

func Aggregate(observations []Observation, windowSize time.Duration) ([]Window, error) {
	if windowSize <= 0 {
		return nil, errors.New("window size must be positive")
	}

	byKey := make(map[aggregateKey]*Window)
	for _, observation := range observations {
		if observation.ObservedAt.IsZero() {
			return nil, errors.New("observation time is required")
		}

		start := observation.ObservedAt.UTC().Truncate(windowSize)
		key := aggregateKey{Start: start, Flow: observation.Flow}
		window, ok := byKey[key]
		if !ok {
			window = &Window{
				SchemaVersion: SchemaVersion,
				WindowStart:   start,
				WindowEnd:     start.Add(windowSize),
				Flow:          observation.Flow,
			}
			byKey[key] = window
		}
		window.add(observation)
	}

	windows := make([]Window, 0, len(byKey))
	for _, window := range byKey {
		windows = append(windows, *window)
	}
	sort.Slice(windows, func(i, j int) bool {
		left, right := windows[i], windows[j]
		if !left.WindowStart.Equal(right.WindowStart) {
			return left.WindowStart.Before(right.WindowStart)
		}
		if left.Flow.NodeName != right.Flow.NodeName {
			return left.Flow.NodeName < right.Flow.NodeName
		}
		if left.Flow.Protocol != right.Flow.Protocol {
			return left.Flow.Protocol < right.Flow.Protocol
		}
		if left.Flow.Direction != right.Flow.Direction {
			return left.Flow.Direction < right.Flow.Direction
		}
		if left.Flow.Source.Address != right.Flow.Source.Address {
			return left.Flow.Source.Address < right.Flow.Source.Address
		}
		if left.Flow.Source.Port != right.Flow.Source.Port {
			return left.Flow.Source.Port < right.Flow.Source.Port
		}
		if left.Flow.Destination.Address != right.Flow.Destination.Address {
			return left.Flow.Destination.Address < right.Flow.Destination.Address
		}
		return left.Flow.Destination.Port < right.Flow.Destination.Port
	})
	return windows, nil
}

func (window *Window) add(observation Observation) {
	if window.LastObservedAt.IsZero() || observation.ObservedAt.After(window.LastObservedAt) {
		window.LastObservedAt = observation.ObservedAt.UTC()
	}
	window.BytesTx += observation.BytesTx
	window.BytesRx += observation.BytesRx
	window.PacketsTx += observation.PacketsTx
	window.PacketsRx += observation.PacketsRx
	window.Retransmissions += observation.Retransmissions
	window.Losses += observation.Losses
	window.RTT = window.RTT.Merge(observation.RTT)
	window.Jitter = window.Jitter.Merge(observation.Jitter)
}
