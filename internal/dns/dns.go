// Package dns parses DNS datagrams captured by the eBPF collector and
// correlates queries with their responses so every name resolution becomes an
// observed transaction (query name, response code, latency).
package dns

import (
	"container/heap"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
)

const SchemaVersion = "network.dns/v1alpha1"

const (
	OutcomeResponse     = "response"
	OutcomeNoResponse   = "no_response"
	OutcomeParseError   = "parse_failed"
	OutcomeIncomplete   = "incomplete"
	ReasonCaptureEnded  = "capture_ended"
	ReasonStateCapacity = "state_capacity"

	defaultTimeout    = 5 * time.Second
	defaultMaxPending = 16384
)

// Fragment is one captured DNS datagram. Source and Destination follow the
// datagram direction: for a query the source is the client, for a response
// the source is the server.
type Fragment struct {
	ObservedAt          time.Time
	KernelTimestampNS   uint64
	NodeName            string
	ObserverPID         uint32
	Process             *flow.Process
	SourceResolved      *flow.ResolvedEndpoint
	DestinationResolved *flow.ResolvedEndpoint
	SourcePod           *flow.Pod
	DestinationPod      *flow.Pod
	ObserverPod         *flow.Pod
	Source              flow.Endpoint
	Destination         flow.Endpoint
	Payload             []byte
}

// Message is the parsed header and first question of a DNS datagram.
type Message struct {
	ID           uint16
	Response     bool
	ResponseCode uint8
	QuestionName string
	QuestionType uint16
}

// Transaction is one correlated DNS exchange (or a query that never received
// a response before the timeout).
type Transaction struct {
	SchemaVersion  string                 `json:"schemaVersion"`
	ObservedAt     time.Time              `json:"observedAt"`
	NodeName       string                 `json:"nodeName"`
	ObserverPID    uint32                 `json:"observerPid,omitempty"`
	Process        *flow.Process          `json:"process,omitempty"`
	ClientResolved *flow.ResolvedEndpoint `json:"clientResolved,omitempty"`
	ServerResolved *flow.ResolvedEndpoint `json:"serverResolved,omitempty"`
	ClientPod      *flow.Pod              `json:"clientPod,omitempty"`
	ServerPod      *flow.Pod              `json:"serverPod,omitempty"`
	ObserverPod    *flow.Pod              `json:"observerPod,omitempty"`
	Protocol       string                 `json:"protocol"`
	Client         flow.Endpoint          `json:"client"`
	Server         flow.Endpoint          `json:"server"`
	QueryName      string                 `json:"queryName,omitempty"`
	QueryType      string                 `json:"queryType,omitempty"`
	Outcome        string                 `json:"outcome"`
	Reason         string                 `json:"reason,omitempty"`
	ResponseCode   string                 `json:"responseCode,omitempty"`
	// LatencyMeasured requires a matched query and nonzero, ordered timestamps.
	// A measured sub-microsecond duration has LatencyMicros == 0.
	LatencyMeasured bool   `json:"latencyMeasured,omitempty"`
	LatencyMicros   uint64 `json:"latencyMicros,omitempty"`
}

// Parse decodes the DNS header and the first question section. Compressed
// question names and truncated payloads are rejected.
func Parse(payload []byte) (Message, error) {
	if len(payload) < 12 {
		return Message{}, errors.New("datagram shorter than DNS header")
	}
	flags := binary.BigEndian.Uint16(payload[2:4])
	message := Message{
		ID:           binary.BigEndian.Uint16(payload[0:2]),
		Response:     flags&0x8000 != 0,
		ResponseCode: uint8(flags & 0x000f),
	}
	questionCount := binary.BigEndian.Uint16(payload[4:6])
	if questionCount == 0 {
		return message, nil
	}

	name, offset, err := parseName(payload, 12)
	if err != nil {
		return Message{}, err
	}
	if offset+4 > len(payload) {
		return Message{}, errors.New("question section truncated")
	}
	message.QuestionName = name
	message.QuestionType = binary.BigEndian.Uint16(payload[offset : offset+2])
	return message, nil
}

// ValidQuestionName is the captured/exported name policy, not hostname syntax.
// Empty means unknown/root; supported nonempty names are bounded visible ASCII.
func ValidQuestionName(name string) bool {
	if len(name) > 253 {
		return false
	}
	for i := range name {
		if name[i] < 33 || name[i] > 126 {
			return false
		}
	}
	return true
}

func parseName(payload []byte, offset int) (string, int, error) {
	var name []byte
	for {
		if offset >= len(payload) {
			return "", 0, errors.New("name runs past datagram end")
		}
		length := int(payload[offset])
		if length == 0 {
			return string(name), offset + 1, nil
		}
		if length&0xc0 != 0 {
			return "", 0, errors.New("compressed question name is not supported")
		}
		offset++
		if offset+length > len(payload) {
			return "", 0, errors.New("label runs past datagram end")
		}
		nameLength := len(name) + length
		if len(name) > 0 {
			nameLength++
		}
		if nameLength > 253 || !ValidQuestionName(string(payload[offset:offset+length])) {
			return "", 0, errors.New("unsupported question name")
		}
		if len(name) > 0 {
			name = append(name, '.')
		}
		name = append(name, payload[offset:offset+length]...)
		offset += length
	}
}

// ResponseCodeString renders an RCODE using its conventional mnemonic.
func ResponseCodeString(code uint8) string {
	switch code {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", code)
	}
}

// QueryTypeString renders a QTYPE using its conventional mnemonic.
func QueryTypeString(queryType uint16) string {
	switch queryType {
	case 1:
		return "A"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	default:
		return fmt.Sprintf("TYPE%d", queryType)
	}
}

type pendingKey struct {
	Client      flow.Endpoint
	Server      flow.Endpoint
	ID          uint16
	Name        string
	QueryType   uint16
	ObserverPID uint32
	NodeName    string
}

type pendingQuery struct {
	fragment Fragment
	message  Message
	key      pendingKey
	index    int
	sequence uint64
}

// Correlator matches DNS responses to their queries by client/server
// endpoints, transaction ID, and question name. Unanswered queries expire
// after the timeout and are reported as no_response.
type Correlator struct {
	timeout    time.Duration
	maxPending int
	pending    map[pendingKey]*pendingQuery
	deadlines  pendingHeap
	sequence   uint64
}

// Config bounds query lifetime and state. Nonpositive Timeout defaults to five
// seconds; nonpositive MaxPending defaults to 16384 queries.
type Config struct {
	Timeout    time.Duration
	MaxPending int
}

// NewCorrelator retains the legacy timeout constructor and uses the default cap.
func NewCorrelator(timeout time.Duration) *Correlator {
	return NewCorrelatorWithConfig(Config{Timeout: timeout})
}

func NewCorrelatorWithConfig(config Config) *Correlator {
	if config.Timeout <= 0 {
		config.Timeout = defaultTimeout
	}
	if config.MaxPending <= 0 {
		config.MaxPending = defaultMaxPending
	}
	return &Correlator{timeout: config.Timeout, maxPending: config.MaxPending, pending: make(map[pendingKey]*pendingQuery)}
}

// Process consumes one captured datagram and returns any transactions that
// became final: matched responses, expired queries, or parse failures.
func (correlator *Correlator) Process(fragment Fragment) []Transaction {
	transactions := correlator.expire(fragment.ObservedAt)

	message, err := Parse(fragment.Payload)
	payload := fragment.Payload
	fragment = snapshotFragment(fragment)
	if err != nil {
		// Without a complete header, retain only the raw diagnostic tuple;
		// client/server attribution would invent a direction. Observer is independent.
		if len(payload) < 12 {
			fragment.SourceResolved, fragment.DestinationResolved = nil, nil
			fragment.SourcePod, fragment.DestinationPod = nil, nil
		} else if payload[2]&0x80 != 0 {
			// The header establishes response direction even with a malformed question.
			fragment.Source, fragment.Destination = fragment.Destination, fragment.Source
			fragment.SourceResolved, fragment.DestinationResolved = fragment.DestinationResolved, fragment.SourceResolved
			fragment.SourcePod, fragment.DestinationPod = fragment.DestinationPod, fragment.SourcePod
		}
		return append(transactions, Transaction{
			SchemaVersion:  SchemaVersion,
			ObservedAt:     fragment.ObservedAt,
			NodeName:       fragment.NodeName,
			ObserverPID:    fragment.ObserverPID,
			Process:        fragment.Process,
			ClientResolved: fragment.SourceResolved,
			ServerResolved: fragment.DestinationResolved,
			ClientPod:      fragment.SourcePod,
			ServerPod:      fragment.DestinationPod,
			ObserverPod:    fragment.ObserverPod,
			Protocol:       "udp",
			Client:         fragment.Source,
			Server:         fragment.Destination,
			Outcome:        OutcomeParseError,
		})
	}

	if !message.Response {
		key := pendingKey{Client: fragment.Source, Server: fragment.Destination, ID: message.ID, Name: message.QuestionName, QueryType: message.QuestionType, ObserverPID: fragment.ObserverPID, NodeName: fragment.NodeName}
		// An outstanding identical question is a retransmission/duplicate. Retain
		// its first capture, enrichment, and deadline rather than postponing expiry.
		if _, exists := correlator.pending[key]; exists {
			return transactions
		}
		if len(correlator.pending) >= correlator.maxPending {
			transaction := correlator.noResponse(&pendingQuery{fragment: fragment, message: message})
			transaction.Outcome = OutcomeIncomplete
			transaction.Reason = ReasonStateCapacity
			return append(transactions, transaction)
		}

		correlator.sequence++
		query := &pendingQuery{fragment: fragment, message: message, key: key, sequence: correlator.sequence}
		correlator.pending[key] = query
		heap.Push(&correlator.deadlines, query)
		return transactions
	}

	key := pendingKey{Client: fragment.Destination, Server: fragment.Source, ID: message.ID, Name: message.QuestionName, QueryType: message.QuestionType, ObserverPID: fragment.ObserverPID, NodeName: fragment.NodeName}
	transaction := Transaction{
		SchemaVersion:  SchemaVersion,
		ObservedAt:     fragment.ObservedAt,
		NodeName:       fragment.NodeName,
		ObserverPID:    fragment.ObserverPID,
		Protocol:       "udp",
		Process:        fragment.Process,
		ClientResolved: fragment.DestinationResolved,
		ServerResolved: fragment.SourceResolved,
		ClientPod:      fragment.DestinationPod,
		ServerPod:      fragment.SourcePod,
		ObserverPod:    fragment.ObserverPod,
		Client:         fragment.Destination,
		Server:         fragment.Source,
		QueryName:      message.QuestionName,
		QueryType:      QueryTypeString(message.QuestionType),
		Outcome:        OutcomeResponse,
		ResponseCode:   ResponseCodeString(message.ResponseCode),
	}
	if query, ok := correlator.pending[key]; ok {
		correlator.remove(query)
		// Query capture identity wins, including unknown (nil) enrichment.
		transaction.Process = query.fragment.Process
		transaction.ClientResolved = query.fragment.SourceResolved
		transaction.ServerResolved = query.fragment.DestinationResolved
		transaction.ClientPod = query.fragment.SourcePod
		transaction.ServerPod = query.fragment.DestinationPod
		transaction.ObserverPod = query.fragment.ObserverPod
		if query.fragment.KernelTimestampNS != 0 && fragment.KernelTimestampNS >= query.fragment.KernelTimestampNS {
			transaction.LatencyMeasured = true
			transaction.LatencyMicros = (fragment.KernelTimestampNS - query.fragment.KernelTimestampNS) / 1000
		}
	}
	return append(transactions, transaction)
}

// Finish expires aged queries first, then reports fresh queries as incomplete:
// capture ending is not evidence that those queries timed out.
func (correlator *Correlator) Finish(now time.Time) []Transaction {
	transactions := correlator.Expire(now)
	for len(correlator.deadlines) > 0 {
		query := correlator.deadlines[0]
		transaction := correlator.noResponse(query)
		transaction.Outcome = OutcomeIncomplete
		transaction.Reason = ReasonCaptureEnded
		transactions = append(transactions, transaction)
		correlator.remove(query)
	}
	return transactions
}

// Flush retains legacy compatibility: it finalizes every pending query as
// no_response regardless of age. New capture-ending callers should use Finish.
func (correlator *Correlator) Flush() []Transaction {
	var transactions []Transaction
	for len(correlator.deadlines) > 0 {
		query := correlator.deadlines[0]
		transactions = append(transactions, correlator.noResponse(query))
		correlator.remove(query)
	}
	return transactions
}

// Expire finalizes only queries whose observation age is at least the timeout.
// It can be called on an idle capture, without processing another datagram.
func (correlator *Correlator) Expire(now time.Time) []Transaction {
	return correlator.expire(now)
}

func (correlator *Correlator) expire(now time.Time) []Transaction {
	var transactions []Transaction
	for len(correlator.deadlines) > 0 {
		query := correlator.deadlines[0]
		if now.Sub(query.fragment.ObservedAt) < correlator.timeout {
			break
		}
		transactions = append(transactions, correlator.noResponse(query))
		correlator.remove(query)
	}
	return transactions
}

// snapshotFragment owns identity but never retains the raw datagram. Process
// and resolved endpoints currently contain only scalar/string fields.
func snapshotFragment(fragment Fragment) Fragment {
	fragment.Payload = nil
	fragment.SourcePod = snapshotPod(fragment.SourcePod)
	fragment.DestinationPod = snapshotPod(fragment.DestinationPod)
	fragment.ObserverPod = snapshotPod(fragment.ObserverPod)
	fragment.NodeName = strings.Clone(fragment.NodeName)
	fragment.Source.Address = strings.Clone(fragment.Source.Address)
	fragment.Destination.Address = strings.Clone(fragment.Destination.Address)
	if fragment.Process != nil {
		process := *fragment.Process
		process.Cmdline = ""
		fragment.Process = &process
	}
	if fragment.SourceResolved != nil {
		endpoint := *fragment.SourceResolved
		fragment.SourceResolved = &endpoint
	}
	if fragment.DestinationResolved != nil {
		endpoint := *fragment.DestinationResolved
		fragment.DestinationResolved = &endpoint
	}
	return fragment
}

func snapshotPod(pod *flow.Pod) *flow.Pod {
	if pod == nil {
		return nil
	}
	copy := *pod
	return &copy
}

func (correlator *Correlator) noResponse(query *pendingQuery) Transaction {
	return Transaction{
		SchemaVersion:  SchemaVersion,
		ObservedAt:     query.fragment.ObservedAt,
		NodeName:       query.fragment.NodeName,
		ObserverPID:    query.fragment.ObserverPID,
		Process:        query.fragment.Process,
		ClientResolved: query.fragment.SourceResolved,
		ServerResolved: query.fragment.DestinationResolved,
		ClientPod:      query.fragment.SourcePod,
		ServerPod:      query.fragment.DestinationPod,
		ObserverPod:    query.fragment.ObserverPod,
		Protocol:       "udp",
		Client:         query.fragment.Source,
		Server:         query.fragment.Destination,
		QueryName:      query.message.QuestionName,
		QueryType:      QueryTypeString(query.message.QuestionType),
		Outcome:        OutcomeNoResponse,
	}
}
