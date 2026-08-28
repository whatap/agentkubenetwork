package l7

import (
	"bytes"
	"strconv"
	"strings"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
)

const (
	SchemaVersion           = "network.l7/v1alpha1"
	ProtocolHTTP1           = "http1"
	ProtocolHTTP2           = "http2"
	BoundaryResponseHeaders = "request_to_response_headers"
	DropOverlappingRequest  = "overlapping_request"
	DropProtocolUpgrade     = "protocol_upgrade"
	DropResponseTimeout     = "response_timeout"
	DropStateCapacity       = "state_capacity"
	defaultStateTTL         = 30 * time.Second
	defaultSweepEvery       = uint64(256)
	defaultMaxConnections   = 16_384
	defaultMaxHTTP2Streams  = 65_536

	SourceKernelPlaintext Source = "kernel_plaintext"
	SourceOpenSSL         Source = "openssl"
)

type Source string

type Config struct {
	MaxPathBytes             int
	MaxHTTP2BufferedBytes    int
	MaxHTTP2HeaderBlockBytes int
	StateTTL                 time.Duration
	SweepEvery               uint64
	MaxTrackedConnections    int
	MaxHTTP2Streams          int
}

type Fragment struct {
	ObservedAt          time.Time
	KernelTimestampNS   uint64
	NodeName            string
	ObserverPID         uint32
	Source              Source
	SourceEndpoint      flow.Endpoint
	DestinationEndpoint flow.Endpoint
	TotalLength         uint32
	Payload             []byte
	TCPSequence         uint32
}

type Transaction struct {
	SchemaVersion         string       `json:"schemaVersion"`
	ObservedAt            time.Time    `json:"observedAt"`
	Flow                  flow.FlowKey `json:"flow"`
	ObserverPID           uint32       `json:"observerPid,omitempty"`
	Protocol              string       `json:"protocol"`
	Source                Source       `json:"source"`
	Method                string       `json:"method"`
	Path                  string       `json:"path"`
	StatusCode            uint16       `json:"statusCode"`
	StreamID              uint32       `json:"streamId,omitempty"`
	ResponseLatencyMicros uint64       `json:"responseLatencyMicros"`
	LatencyBoundary       string       `json:"latencyBoundary"`
}

type Drop struct {
	SchemaVersion string    `json:"schemaVersion"`
	ObservedAt    time.Time `json:"observedAt"`
	NodeName      string    `json:"nodeName,omitempty"`
	ObserverPID   uint32    `json:"observerPid,omitempty"`
	Protocol      string    `json:"protocol,omitempty"`
	Source        string    `json:"source,omitempty"`
	Outcome       string    `json:"outcome"`
	Reason        string    `json:"reason"`
	Count         uint64    `json:"count,omitempty"`
}

type Output struct {
	Transaction *Transaction
	Drop        *Drop
}

func newDrop(fragment Fragment, protocol, reason string) *Drop {
	return &Drop{
		SchemaVersion: SchemaVersion,
		ObservedAt:    fragment.ObservedAt.UTC(),
		NodeName:      fragment.NodeName,
		ObserverPID:   fragment.ObserverPID,
		Protocol:      protocol,
		Source:        string(fragment.Source),
		Outcome:       "drop",
		Reason:        reason,
		Count:         1,
	}
}

type connectionKey struct {
	NodeName    string
	ObserverPID uint32
	Source      Source
	Client      flow.Endpoint
	Server      flow.Endpoint
}

type pendingHTTP1 struct {
	startedNS uint64
	method    string
	path      string
}

type Correlator struct {
	maxPathBytes             int
	maxHTTP2BufferedBytes    int
	maxHTTP2HeaderBlockBytes int
	stateTTLNS               uint64
	sweepEvery               uint64
	processed                uint64
	maxTrackedConnections    int
	maxHTTP2Streams          int
	http1                    map[connectionKey]pendingHTTP1
	http1Ambiguous           map[connectionKey]uint64
	http2Connections         map[transportKey]uint64
	http2Directions          map[directionKey]*http2DirectionState
	http2                    map[http2StreamKey]pendingHTTP2
}

func NewCorrelator(config Config) *Correlator {
	maxPathBytes := config.MaxPathBytes
	if maxPathBytes <= 0 {
		maxPathBytes = 128
	}
	maxHTTP2BufferedBytes := config.MaxHTTP2BufferedBytes
	if maxHTTP2BufferedBytes <= 0 {
		maxHTTP2BufferedBytes = defaultMaxHTTP2BufferedBytes
	}
	maxHTTP2HeaderBlockBytes := config.MaxHTTP2HeaderBlockBytes
	if maxHTTP2HeaderBlockBytes <= 0 {
		maxHTTP2HeaderBlockBytes = defaultMaxHTTP2HeaderBlock
	}
	stateTTL := config.StateTTL
	if stateTTL <= 0 {
		stateTTL = defaultStateTTL
	}
	sweepEvery := config.SweepEvery
	if sweepEvery == 0 {
		sweepEvery = defaultSweepEvery
	}
	maxTrackedConnections := config.MaxTrackedConnections
	if maxTrackedConnections <= 0 {
		maxTrackedConnections = defaultMaxConnections
	}
	maxHTTP2Streams := config.MaxHTTP2Streams
	if maxHTTP2Streams <= 0 {
		maxHTTP2Streams = defaultMaxHTTP2Streams
	}
	return &Correlator{
		maxPathBytes:             maxPathBytes,
		maxHTTP2BufferedBytes:    maxHTTP2BufferedBytes,
		maxHTTP2HeaderBlockBytes: maxHTTP2HeaderBlockBytes,
		stateTTLNS:               uint64(stateTTL),
		sweepEvery:               sweepEvery,
		maxTrackedConnections:    maxTrackedConnections,
		maxHTTP2Streams:          maxHTTP2Streams,
		http1:                    make(map[connectionKey]pendingHTTP1),
		http1Ambiguous:           make(map[connectionKey]uint64),
		http2Connections:         make(map[transportKey]uint64),
		http2Directions:          make(map[directionKey]*http2DirectionState),
		http2:                    make(map[http2StreamKey]pendingHTTP2),
	}
}

func (correlator *Correlator) Process(fragment Fragment) []Output {
	expired := correlator.expire(fragment)
	if outputs, handled := correlator.processHTTP2(fragment); handled {
		return append(expired, outputs...)
	}
	if method, path, ok := parseHTTP1Request(fragment.Payload, correlator.maxPathBytes); ok {
		key := connectionKey{
			NodeName:    fragment.NodeName,
			ObserverPID: fragment.ObserverPID,
			Source:      fragment.Source,
			Client:      fragment.SourceEndpoint,
			Server:      fragment.DestinationEndpoint,
		}
		if _, ambiguous := correlator.http1Ambiguous[key]; ambiguous {
			return expired
		}
		if containsPipelinedHTTP1Request(fragment.Payload, correlator.maxPathBytes) {
			delete(correlator.http1, key)
			correlator.http1Ambiguous[key] = fragmentTimestampNS(fragment)
			return append(expired, Output{Drop: newDrop(fragment, ProtocolHTTP1, DropOverlappingRequest)})
		}
		if _, pending := correlator.http1[key]; pending {
			delete(correlator.http1, key)
			correlator.http1Ambiguous[key] = fragmentTimestampNS(fragment)
			return append(expired, Output{Drop: newDrop(fragment, ProtocolHTTP1, DropOverlappingRequest)})
		}
		if correlator.trackedConnections() >= correlator.maxTrackedConnections {
			return append(expired, Output{Drop: newDrop(fragment, ProtocolHTTP1, DropStateCapacity)})
		}
		correlator.http1[key] = pendingHTTP1{
			startedNS: fragmentTimestampNS(fragment),
			method:    method,
			path:      path,
		}
		return expired
	}

	statusCode, ok := parseHTTP1Response(fragment.Payload)
	if !ok {
		return expired
	}
	key := connectionKey{
		NodeName:    fragment.NodeName,
		ObserverPID: fragment.ObserverPID,
		Source:      fragment.Source,
		Client:      fragment.DestinationEndpoint,
		Server:      fragment.SourceEndpoint,
	}
	if _, ambiguous := correlator.http1Ambiguous[key]; ambiguous {
		return expired
	}
	if statusCode < 200 && statusCode != 101 {
		return expired
	}
	pending, ok := correlator.http1[key]
	if !ok {
		return expired
	}
	delete(correlator.http1, key)
	if statusCode == 101 {
		return append(expired, Output{Drop: newDrop(fragment, ProtocolHTTP1, DropProtocolUpgrade)})
	}

	completedNS := fragmentTimestampNS(fragment)
	if completedNS <= pending.startedNS {
		return expired
	}
	transaction := &Transaction{
		SchemaVersion: SchemaVersion,
		ObservedAt:    fragment.ObservedAt.UTC(),
		ObserverPID:   fragment.ObserverPID,
		Flow: flow.FlowKey{
			NodeName:    fragment.NodeName,
			Protocol:    "tcp",
			Direction:   "client-to-server",
			Source:      key.Client,
			Destination: key.Server,
		},
		Protocol:              ProtocolHTTP1,
		Source:                fragment.Source,
		Method:                pending.method,
		Path:                  pending.path,
		StatusCode:            statusCode,
		ResponseLatencyMicros: (completedNS - pending.startedNS) / uint64(time.Microsecond),
		LatencyBoundary:       BoundaryResponseHeaders,
	}
	return append(expired, Output{Transaction: transaction})
}

func (correlator *Correlator) expire(fragment Fragment) []Output {
	correlator.processed++
	if correlator.processed%correlator.sweepEvery != 0 {
		return nil
	}
	now := fragmentTimestampNS(fragment)
	if now == 0 {
		return nil
	}
	outputs := make([]Output, 0)
	for key, pending := range correlator.http1 {
		if !expiredAt(now, pending.startedNS, correlator.stateTTLNS) {
			continue
		}
		delete(correlator.http1, key)
		outputs = append(outputs, Output{Drop: newConnectionDrop(fragment.ObservedAt, key, ProtocolHTTP1, DropResponseTimeout)})
	}
	for key, ambiguousAt := range correlator.http1Ambiguous {
		if expiredAt(now, ambiguousAt, correlator.stateTTLNS) {
			delete(correlator.http1Ambiguous, key)
		}
	}
	for key, pending := range correlator.http2 {
		if !expiredAt(now, pending.startedNS, correlator.stateTTLNS) {
			continue
		}
		delete(correlator.http2, key)
		outputs = append(outputs, Output{Drop: newConnectionDrop(fragment.ObservedAt, key.Connection, ProtocolHTTP2, DropResponseTimeout)})
	}
	for key, state := range correlator.http2Directions {
		if expiredAt(now, state.lastSeenNS, correlator.stateTTLNS) {
			delete(correlator.http2Directions, key)
		}
	}
	for key, lastSeenNS := range correlator.http2Connections {
		if expiredAt(now, lastSeenNS, correlator.stateTTLNS) {
			delete(correlator.http2Connections, key)
		}
	}
	return outputs
}

func expiredAt(now, started, ttl uint64) bool {
	return started != 0 && now >= started && now-started >= ttl
}

func newConnectionDrop(observedAt time.Time, key connectionKey, protocol, reason string) *Drop {
	return &Drop{
		SchemaVersion: SchemaVersion,
		ObservedAt:    observedAt.UTC(),
		NodeName:      key.NodeName,
		ObserverPID:   key.ObserverPID,
		Protocol:      protocol,
		Source:        string(key.Source),
		Outcome:       "drop",
		Reason:        reason,
		Count:         1,
	}
}

func (correlator *Correlator) trackedConnections() int {
	return len(correlator.http1) + len(correlator.http1Ambiguous) + len(correlator.http2Connections)
}

func (correlator *Correlator) processHTTP2(fragment Fragment) ([]Output, bool) {
	transport := makeTransportKey(fragment)
	payload := fragment.Payload
	timestampNS := fragmentTimestampNS(fragment)
	_, active := correlator.http2Connections[transport]
	if !active {
		if !bytes.HasPrefix(payload, []byte(http2ClientPreface)) {
			return nil, false
		}
		if correlator.trackedConnections() >= correlator.maxTrackedConnections {
			return []Output{{Drop: newDrop(fragment, ProtocolHTTP2, DropStateCapacity)}}, true
		}
		correlator.http2Connections[transport] = timestampNS
		payload = payload[len(http2ClientPreface):]
	} else {
		correlator.http2Connections[transport] = timestampNS
	}

	direction := directionKey{
		Transport: transport,
		From:      fragment.SourceEndpoint,
		To:        fragment.DestinationEndpoint,
	}
	state := correlator.http2Directions[direction]
	if state == nil {
		state = newHTTP2DirectionState(correlator.maxHTTP2BufferedBytes, correlator.maxHTTP2HeaderBlockBytes)
		correlator.http2Directions[direction] = state
	}
	state.lastSeenNS = timestampNS
	if state.poisoned {
		return nil, true
	}
	if fragment.TotalLength > 0 && fragment.TotalLength > uint32(len(fragment.Payload)) {
		state.poison()
		return []Output{{Drop: newDrop(fragment, ProtocolHTTP2, DropHTTP2StreamDesync)}}, true
	}
	blocks, err := state.feed(payload, timestampNS)
	if err != nil {
		state.poison()
		return []Output{{Drop: newDrop(fragment, ProtocolHTTP2, DropHTTP2StreamDesync)}}, true
	}

	outputs := make([]Output, 0, len(blocks))
	for _, block := range blocks {
		method, path, status, ok := http2Identity(block.fields, correlator.maxPathBytes)
		if !ok {
			continue
		}
		if method != "" {
			key := http2StreamKey{
				Connection: connectionKey{
					NodeName:    fragment.NodeName,
					ObserverPID: fragment.ObserverPID,
					Source:      fragment.Source,
					Client:      fragment.SourceEndpoint,
					Server:      fragment.DestinationEndpoint,
				},
				StreamID: block.streamID,
			}
			if _, exists := correlator.http2[key]; exists {
				delete(correlator.http2, key)
				outputs = append(outputs, Output{Drop: newDrop(fragment, ProtocolHTTP2, DropInvalidHTTP2)})
				continue
			}
			if len(correlator.http2) >= correlator.maxHTTP2Streams {
				outputs = append(outputs, Output{Drop: newDrop(fragment, ProtocolHTTP2, DropStateCapacity)})
				continue
			}
			correlator.http2[key] = pendingHTTP2{startedNS: block.startedNS, method: method, path: path}
			continue
		}

		if status < 200 {
			continue
		}
		key := http2StreamKey{
			Connection: connectionKey{
				NodeName:    fragment.NodeName,
				ObserverPID: fragment.ObserverPID,
				Source:      fragment.Source,
				Client:      fragment.DestinationEndpoint,
				Server:      fragment.SourceEndpoint,
			},
			StreamID: block.streamID,
		}
		pending, exists := correlator.http2[key]
		if !exists {
			continue
		}
		delete(correlator.http2, key)
		completedNS := block.startedNS
		if completedNS <= pending.startedNS {
			outputs = append(outputs, Output{Drop: newDrop(fragment, ProtocolHTTP2, DropInvalidLatency)})
			continue
		}
		outputs = append(outputs, Output{Transaction: &Transaction{
			SchemaVersion: SchemaVersion,
			ObservedAt:    fragment.ObservedAt.UTC(),
			ObserverPID:   fragment.ObserverPID,
			Flow: flow.FlowKey{
				NodeName:    fragment.NodeName,
				Protocol:    "tcp",
				Direction:   "client-to-server",
				Source:      key.Connection.Client,
				Destination: key.Connection.Server,
			},
			Protocol:              ProtocolHTTP2,
			Source:                fragment.Source,
			Method:                pending.method,
			Path:                  pending.path,
			StatusCode:            status,
			StreamID:              block.streamID,
			ResponseLatencyMicros: (completedNS - pending.startedNS) / uint64(time.Microsecond),
			LatencyBoundary:       BoundaryResponseHeaders,
		}})
	}
	return outputs, true
}

func dropReason(err error) string {
	message := err.Error()
	for _, reason := range []string{DropHTTP2HeaderBlockTooLarge, DropInvalidHTTP2} {
		if strings.HasPrefix(message, reason) {
			return reason
		}
	}
	return DropInvalidHTTP2
}

func fragmentTimestampNS(fragment Fragment) uint64 {
	if fragment.KernelTimestampNS != 0 {
		return fragment.KernelTimestampNS
	}
	if fragment.ObservedAt.IsZero() {
		return 0
	}
	return uint64(fragment.ObservedAt.UnixNano())
}

func parseHTTP1Request(payload []byte, maxPathBytes int) (method, path string, ok bool) {
	line := firstLine(payload)
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/1.") || !isHTTPMethod(parts[0]) {
		return "", "", false
	}
	path = parts[1]
	if query := strings.IndexByte(path, '?'); query >= 0 {
		path = path[:query]
	}
	if path == "" || path[0] != '/' {
		return "", "", false
	}
	if len(path) > maxPathBytes {
		path = path[:maxPathBytes]
	}
	return parts[0], path, true
}

func containsPipelinedHTTP1Request(payload []byte, maxPathBytes int) bool {
	firstHeaderEnd := bytes.Index(payload, []byte("\r\n\r\n"))
	if firstHeaderEnd < 0 {
		return false
	}
	_, _, ok := parseHTTP1Request(payload[firstHeaderEnd+4:], maxPathBytes)
	return ok
}

func parseHTTP1Response(payload []byte) (uint16, bool) {
	line := firstLine(payload)
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/1.") || len(parts[1]) != 3 {
		return 0, false
	}
	status, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil || status < 100 || status > 599 {
		return 0, false
	}
	return uint16(status), true
}

func firstLine(payload []byte) string {
	if end := bytes.Index(payload, []byte("\r\n")); end >= 0 {
		return string(payload[:end])
	}
	return string(payload)
}

func isHTTPMethod(method string) bool {
	switch method {
	case "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT":
		return true
	default:
		return false
	}
}
