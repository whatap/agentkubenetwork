package flow

import (
	"cmp"
	"errors"
	"sort"
	"time"
)

const SchemaVersion = "network.flow/v1alpha1"

type Endpoint struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
}

// ResolvedEndpoint is a NAT-translated endpoint attached next to the raw
// socket endpoints. Via records the resolution mechanism (e.g. "conntrack").
type ResolvedEndpoint struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
	Via     string `json:"via"`
}

// Process identifies the userspace process that issued the socket call the
// kernel event was sampled from. PID is always the host (init namespace) PID
// reported by the kernel; the remaining fields are only populated when the
// userspace resolver could read /proc for that PID, with Via recording the
// mechanism (e.g. "procfs"). StartTimeTicks disambiguates PID reuse.
type Process struct {
	PID            uint32 `json:"pid"`
	StartTimeTicks uint64 `json:"startTimeTicks,omitempty"`
	Comm           string `json:"comm,omitempty"`
	Cmdline        string `json:"cmdline,omitempty"`
	ContainerID    string `json:"containerId,omitempty"`
	Via            string `json:"via,omitempty"`
}

type FlowKey struct {
	NodeName    string   `json:"nodeName"`
	Protocol    string   `json:"protocol"`
	Direction   string   `json:"direction"`
	Source      Endpoint `json:"source"`
	Destination Endpoint `json:"destination"`
}

type Observation struct {
	SourcePod           *Pod              `json:"sourcePod,omitempty"`
	DestinationPod      *Pod              `json:"destinationPod,omitempty"`
	ObserverPod         *Pod              `json:"observerPod,omitempty"`
	ObservedAt          time.Time         `json:"observedAt"`
	KernelTimestampNS   uint64            `json:"kernelTimestampNs,omitempty"`
	Flow                FlowKey           `json:"flow"`
	SourceResolved      *ResolvedEndpoint `json:"sourceResolved,omitempty"`
	DestinationResolved *ResolvedEndpoint `json:"destinationResolved,omitempty"`
	Process             *Process          `json:"process,omitempty"`
	BytesTx             uint64            `json:"bytesTx"`
	BytesRx             uint64            `json:"bytesRx"`
	PacketsTx           uint64            `json:"packetsTx"`
	PacketsRx           uint64            `json:"packetsRx"`
	Retransmissions     uint64            `json:"retransmissions"`
	Losses              uint64            `json:"losses"`
	RTT                 Distribution      `json:"rtt"`
	Jitter              Distribution      `json:"jitter"`
}

type Window struct {
	SourcePod           *Pod              `json:"sourcePod,omitempty"`
	DestinationPod      *Pod              `json:"destinationPod,omitempty"`
	ObserverPod         *Pod              `json:"observerPod,omitempty"`
	SchemaVersion       string            `json:"schemaVersion"`
	Partial             bool              `json:"partial,omitempty"`
	WindowStart         time.Time         `json:"windowStart"`
	WindowEnd           time.Time         `json:"windowEnd"`
	LastObservedAt      time.Time         `json:"lastObservedAt"`
	Flow                FlowKey           `json:"flow"`
	SourceResolved      *ResolvedEndpoint `json:"sourceResolved,omitempty"`
	DestinationResolved *ResolvedEndpoint `json:"destinationResolved,omitempty"`
	// Process is the observer, not necessarily the canonical source endpoint.
	// Comm is retained and grouped exactly (including missing values), avoiding
	// arrival-order-dependent names. Command lines are neither grouped nor emitted.
	Process *Process `json:"process,omitempty"`
	BytesTx uint64   `json:"bytesTx"`
	// ObservationCount counts input records, not TCP connections or RTT samples.
	ObservationCount uint64       `json:"observationCount"`
	BytesRx          uint64       `json:"bytesRx"`
	PacketsTx        uint64       `json:"packetsTx"`
	PacketsRx        uint64       `json:"packetsRx"`
	Retransmissions  uint64       `json:"retransmissions"`
	Losses           uint64       `json:"losses"`
	RTT              Distribution `json:"rtt"`
	Jitter           Distribution `json:"jitter"`
}

type aggregateKey struct {
	SourcePod              Pod
	DestinationPod         Pod
	ObserverPod            Pod
	Start                  time.Time
	Flow                   FlowKey
	HasSourceResolved      bool
	SourceResolved         ResolvedEndpoint
	HasDestinationResolved bool
	DestinationResolved    ResolvedEndpoint
	HasProcess             bool
	Process                Process
}

func keyFor(observation Observation, windowSize time.Duration) aggregateKey {
	key := aggregateKey{Start: observation.ObservedAt.UTC().Truncate(windowSize), Flow: observation.Flow}
	if observation.SourcePod != nil {
		key.SourcePod = *observation.SourcePod
	}
	if observation.DestinationPod != nil {
		key.DestinationPod = *observation.DestinationPod
	}
	if observation.ObserverPod != nil {
		key.ObserverPod = *observation.ObserverPod
	}
	if observation.SourceResolved != nil {
		key.HasSourceResolved = true
		key.SourceResolved = *observation.SourceResolved
	}
	if observation.DestinationResolved != nil {
		key.HasDestinationResolved = true
		key.DestinationResolved = *observation.DestinationResolved
	}
	if observation.Process != nil {
		key.HasProcess = true
		key.Process = *observation.Process
		key.Process.Cmdline = ""
	}
	return key
}

func (key aggregateKey) newWindow(windowSize time.Duration) *Window {
	window := &Window{
		SchemaVersion: SchemaVersion,
		WindowStart:   key.Start,
		WindowEnd:     key.Start.Add(windowSize),
		Flow:          key.Flow,
	}
	// key is a value copy: neither inputs nor other windows share these pointers.
	if key.SourcePod.UID != "" {
		window.SourcePod = &key.SourcePod
	}
	if key.DestinationPod.UID != "" {
		window.DestinationPod = &key.DestinationPod
	}
	if key.ObserverPod.UID != "" {
		window.ObserverPod = &key.ObserverPod
	}
	if key.HasSourceResolved {
		window.SourceResolved = &key.SourceResolved
	}
	if key.HasDestinationResolved {
		window.DestinationResolved = &key.DestinationResolved
	}
	if key.HasProcess {
		window.Process = &key.Process
	}
	return window
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

		key := keyFor(observation, windowSize)
		window, ok := byKey[key]
		if !ok {
			window = key.newWindow(windowSize)
			byKey[key] = window
		}
		window.add(observation)
	}

	windows := make([]Window, 0, len(byKey))
	for _, window := range byKey {
		windows = append(windows, *window)
	}
	sortWindows(windows)
	return windows, nil
}

func sortWindows(windows []Window) {
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
		return cmp.Or(
			cmp.Compare(left.Flow.Destination.Port, right.Flow.Destination.Port),
			compareResolved(left.SourceResolved, right.SourceResolved),
			compareResolved(left.DestinationResolved, right.DestinationResolved),
			compareProcess(left.Process, right.Process),
			comparePod(left.SourcePod, right.SourcePod),
			comparePod(left.DestinationPod, right.DestinationPod),
			comparePod(left.ObserverPod, right.ObserverPod),
		) < 0
	})
}

func compareResolved(left, right *ResolvedEndpoint) int {
	if left == nil && right == nil {
		return 0
	}
	if left == nil {
		return -1
	}
	if right == nil {
		return 1
	}
	return cmp.Or(cmp.Compare(left.Address, right.Address), cmp.Compare(left.Port, right.Port), cmp.Compare(left.Via, right.Via))
}

func compareProcess(left, right *Process) int {
	if left == nil && right == nil {
		return 0
	}
	if left == nil {
		return -1
	}
	if right == nil {
		return 1
	}
	return cmp.Or(
		cmp.Compare(left.PID, right.PID),
		cmp.Compare(left.StartTimeTicks, right.StartTimeTicks),
		cmp.Compare(left.ContainerID, right.ContainerID),
		cmp.Compare(left.Via, right.Via),
		cmp.Compare(left.Comm, right.Comm),
	)
}

func (window *Window) add(observation Observation) {
	window.ObservationCount++
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
