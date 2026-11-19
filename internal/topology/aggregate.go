// Package topology aggregates presence evidence, not request counts or rates.
// It is single-threaded; the application owns observation and flush ordering.
package topology

import (
	"cmp"
	"errors"
	"sort"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
)

const (
	SchemaVersion         = "network.topology/v1alpha1"
	KindUnresolvedAddress = "unresolved_address"
	DirectionUnknown      = "unknown"
	DirectionRequest      = "request"
)

// Config has no defaults; callers resolve them. ClusterID names the cluster in
// every summary. One WhaTap Kubernetes project monitors one cluster, so the
// agent defaults it to the license project code. It is never a node name or
// storage OID.
type Config struct {
	ClusterID  string
	WindowSize time.Duration
	MaxEntries int
}

// Endpoint is either a complete workload identity or an unresolved address.
// Workloads have no Address: individual replica addresses must not split them.
// An unresolved endpoint is not a claim that the peer is outside Kubernetes.
type Endpoint struct {
	Kind      string `json:"kind"`
	UID       string `json:"uid,omitempty"`
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Address   string `json:"address,omitempty"`
}

// Summary stores monotone evidence. Reduce flags with OR/MAX and LastSeenMS
// with MAX, including across OIDs and repeated/late records. Never SUM them.
// False ResultObserved means no confirmed result, not a successful request.
// False ErrorObserved does not establish health without ResultObserved.
type Summary struct {
	ClusterID       string    `json:"clusterId"`
	WindowStart     time.Time `json:"windowStart"`
	WindowEnd       time.Time `json:"windowEnd"`
	Source          Endpoint  `json:"source"`
	Destination     Endpoint  `json:"destination"`
	Transport       string    `json:"transport"`
	Protocol        string    `json:"protocol"`
	Direction       string    `json:"direction"`
	DestinationPort uint16    `json:"destinationPort,omitempty"`
	Observed        bool      `json:"observed"`
	ResultObserved  bool      `json:"resultObserved"`
	ErrorObserved   bool      `json:"errorObserved"`
	LastSeenMS      int64     `json:"lastSeenMs"`
}

type entryKey struct {
	start                          time.Time
	source, destination            Endpoint
	transport, protocol, direction string
	port                           uint16
}

type Aggregator struct {
	config  Config
	entries map[entryKey]Summary
}

// ErrCapacity rejects a new relationship/bucket without evicting evidence.
// Callers must surface it as lost coverage, not render a healthy partial graph.
var ErrCapacity = errors.New("topology entry capacity reached")

// ErrInvalidObservation means no evidence from the input was retained.
var ErrInvalidObservation = errors.New("invalid topology observation")

// ErrNotQueued is returned by an exporter that has no room for a summary. The
// summary is not lost: the caller still owns it and offers it again.
var ErrNotQueued = errors.New("topology summary was not queued")

func New(config Config) (*Aggregator, error) {
	if !validText(config.ClusterID, 253) || config.MaxEntries <= 0 || config.MaxEntries > 65536 ||
		config.WindowSize < time.Millisecond || config.WindowSize > time.Minute || config.WindowSize%time.Millisecond != 0 {
		return nil, errors.New("topology requires explicit cluster ID (1..253 printable ASCII bytes without whitespace), positive capacity and whole-ms window in [1ms,60s]")
	}
	return &Aggregator{config: config, entries: make(map[entryKey]Summary)}, nil
}

func validText(s string, limit int) bool {
	if len(s) == 0 || len(s) > limit {
		return false
	}
	for i := range s {
		if s[i] < 33 || s[i] > 126 {
			return false
		}
	}
	return true
}

// ObserveWindow contributes presence at LastObservedAt, not WindowEnd. A raw
// L4 window is not a request: endpoint ordering and ports establish no client
// or server role, even when Flow.Direction describes local ingress/egress.
func (a *Aggregator) ObserveWindow(w flow.Window) error {
	if w.SchemaVersion != flow.SchemaVersion || w.Flow.Protocol != "tcp" || w.ObservationCount == 0 ||
		!validTime(w.WindowStart) || !validTime(w.WindowEnd) || !validTime(w.LastObservedAt) ||
		!w.WindowEnd.After(w.WindowStart) || w.LastObservedAt.Before(w.WindowStart) || !w.LastObservedAt.Before(w.WindowEnd) ||
		!validRawEndpoint(w.Flow.Source) || !validRawEndpoint(w.Flow.Destination) ||
		!validResolved(w.SourceResolved) || !validResolved(w.DestinationResolved) {
		return ErrInvalidObservation
	}
	source := endpointFor(w.SourcePod, w.Flow.Source, w.SourceResolved)
	destination := endpointFor(w.DestinationPod, w.Flow.Destination, w.DestinationResolved)
	if compareEndpoint(source, destination) > 0 {
		source, destination = destination, source
	}
	return a.observe(w.LastObservedAt, Summary{Source: source, Destination: destination,
		Transport: "tcp", Protocol: "tcp", Direction: DirectionUnknown})
}

func endpointFor(pod *flow.Pod, raw flow.Endpoint, resolved *flow.ResolvedEndpoint) Endpoint {
	if pod != nil && pod.WorkloadUID != "" && pod.WorkloadName != "" && pod.WorkloadKind != "" && pod.Namespace != "" {
		return Endpoint{Kind: pod.WorkloadKind, Namespace: pod.Namespace, Name: pod.WorkloadName, UID: pod.WorkloadUID}
	}
	address := raw.Address
	if resolved != nil {
		address = resolved.Address
	}
	return Endpoint{Kind: KindUnresolvedAddress, Address: address}
}

func (a *Aggregator) observe(at time.Time, s Summary) error {
	if !validTime(at) || !validEndpoint(s.Source) || !validEndpoint(s.Destination) {
		return ErrInvalidObservation
	}
	s.ClusterID = a.config.ClusterID
	s.WindowStart = at.UTC().Truncate(a.config.WindowSize)
	s.WindowEnd = s.WindowStart.Add(a.config.WindowSize)
	s.LastSeenMS, s.Observed = at.UnixMilli(), true
	key := entryKey{s.WindowStart, s.Source, s.Destination, s.Transport, s.Protocol, s.Direction, s.DestinationPort}
	if previous, ok := a.entries[key]; ok {
		previous.LastSeenMS = max(previous.LastSeenMS, s.LastSeenMS)
		previous.Observed = previous.Observed || s.Observed
		previous.ResultObserved = previous.ResultObserved || s.ResultObserved
		previous.ErrorObserved = previous.ErrorObserved || s.ErrorObserved
		a.entries[key] = previous
	} else {
		if len(a.entries) >= a.config.MaxEntries {
			return ErrCapacity
		}
		a.entries[key] = s
	}
	return nil
}

// FlushBefore drains only nominal half-open buckets whose end is <= watermark.
// Late observations may reopen an already drained bucket as a MAX-safe
// correction; there is no unbounded retained history or silent late-event drop.
func (a *Aggregator) FlushBefore(watermark time.Time) []Summary {
	return a.flush(func(s Summary) bool { return !s.WindowEnd.After(watermark) })
}

// FlushAll drains remaining presence evidence, including a partial final
// bucket. WindowEnd remains the nominal boundary, NOT proof of full capture.
// This is safe for positive evidence flags, never counts, rates or absence.
func (a *Aggregator) FlushAll() []Summary {
	return a.flush(func(Summary) bool { return true })
}

func (a *Aggregator) flush(eligible func(Summary) bool) []Summary {
	var result []Summary
	for key, s := range a.entries {
		if eligible(s) {
			result = append(result, s)
			delete(a.entries, key)
		}
	}
	sort.Slice(result, func(i, j int) bool { return compareSummary(result[i], result[j]) < 0 })
	return result
}

func (a *Aggregator) Len() int { return len(a.entries) }

func compareEndpoint(a, b Endpoint) int {
	return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Namespace, b.Namespace),
		cmp.Compare(a.Name, b.Name), cmp.Compare(a.UID, b.UID), cmp.Compare(a.Address, b.Address))
}

func compareSummary(a, b Summary) int {
	return cmp.Or(a.WindowStart.Compare(b.WindowStart), compareEndpoint(a.Source, b.Source),
		compareEndpoint(a.Destination, b.Destination), cmp.Compare(a.Transport, b.Transport),
		cmp.Compare(a.Protocol, b.Protocol), cmp.Compare(a.Direction, b.Direction),
		cmp.Compare(a.DestinationPort, b.DestinationPort))
}
