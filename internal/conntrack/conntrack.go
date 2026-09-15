// Package conntrack resolves NAT-translated flow tuples (e.g. Kubernetes
// Service ClusterIP DNAT) into the real backend endpoints by reading the
// kernel connection-tracking table over ctnetlink.
package conntrack

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
)

const Via = "conntrack"

const (
	ctaTupleOrig  = 1
	ctaTupleReply = 2

	ctaTupleIP    = 1
	ctaTupleProto = 2

	ctaIPv4Src = 1
	ctaIPv4Dst = 2
	ctaIPv6Src = 3
	ctaIPv6Dst = 4

	ctaProtoNum     = 1
	ctaProtoSrcPort = 2
	ctaProtoDstPort = 3

	nlaTypeMask = 0x3fff

	nlmsgHeaderLength = 16
	nfgenmsgLength    = 4

	nlmsgError   = 2
	nlmsgDone    = 3
	nlmFDumpIntr = 0x10

	protocolNumberTCP = 6
	protocolNumberUDP = 17
)

// Tuple is one direction of a conntrack entry.
type Tuple struct {
	Protocol    uint8
	Source      flow.Endpoint
	Destination flow.Endpoint
}

// Entry pairs the original (pre-NAT) and reply (post-NAT) tuples.
type Entry struct {
	Original Tuple
	Reply    Tuple
}

type lookupKey struct {
	protocol           uint8
	sourceAddress      string
	sourcePort         uint16
	destinationAddress string
	destinationPort    uint16
}

type dumpFunc func() ([]Entry, error)

// Resolver caches a periodically refreshed conntrack dump and answers
// original-tuple lookups with the NAT-translated backend endpoint.
type Resolver struct {
	mu          sync.Mutex
	dump        dumpFunc
	ttl         time.Duration
	missRefresh time.Duration
	now         func() time.Time
	refreshAt   time.Time
	dumpedAt    time.Time
	table       map[lookupKey]flow.Endpoint
}

// minMissRefresh bounds how often a lookup miss may force a fresh dump.
// Short-lived client connections (one HTTP request per TCP connection) are
// usually created and closed between two periodic dumps, so a miss re-reads
// the table instead of waiting for the next scheduled refresh.
const (
	minMissRefresh = 20 * time.Millisecond
	maxMissRefresh = 25 * time.Millisecond
)

func newResolver(dump dumpFunc, ttl time.Duration, now func() time.Time) *Resolver {
	if ttl <= 0 {
		ttl = time.Second
	}
	if now == nil {
		now = time.Now
	}
	missRefresh := ttl / 10
	if missRefresh < minMissRefresh {
		missRefresh = minMissRefresh
	}
	if missRefresh > maxMissRefresh {
		missRefresh = maxMissRefresh
	}
	return &Resolver{dump: dump, ttl: ttl, missRefresh: missRefresh, now: now}
}

// Resolve reports the NAT-translated destination for the original flow
// (source → destination). It only returns a value when the kernel conntrack
// reply tuple proves the destination was rewritten (DNAT).
func (resolver *Resolver) Resolve(protocol string, source, destination flow.Endpoint) (flow.Endpoint, string, bool) {
	return resolver.ResolveAfter(protocol, source, destination, time.Time{})
}

// ResolveAfter prevents a newly established socket from inheriting a tuple's
// cached backend from before its establishment. The caller retries boundedly
// when refreshing is throttled; no old mapping is returned in that interval.
func (resolver *Resolver) ResolveAfter(protocol string, source, destination flow.Endpoint, observedAt time.Time) (flow.Endpoint, string, bool) {
	number, ok := protocolNumber(protocol)
	if !ok {
		return flow.Endpoint{}, "", false
	}
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	resolver.refreshLocked()
	key := lookupKey{
		protocol:           number,
		sourceAddress:      source.Address,
		sourcePort:         source.Port,
		destinationAddress: destination.Address,
		destinationPort:    destination.Port,
	}
	resolved, ok := resolver.table[key]
	if (!ok || resolver.dumpedAt.Before(observedAt)) && resolver.refreshOnMissLocked() {
		resolved, ok = resolver.table[key]
	}
	if !ok || resolver.dumpedAt.Before(observedAt) {
		return flow.Endpoint{}, "", false
	}
	return resolved, Via, true
}

// refreshOnMissLocked re-dumps the table for a lookup miss when the current
// table is older than missRefresh. It reports whether a fresh dump was loaded.
// A failed dump invalidates old proof and starts the same backoff as a
// scheduled refresh failure.
func (resolver *Resolver) refreshOnMissLocked() bool {
	now := resolver.now()
	if resolver.dumpedAt.IsZero() || now.Sub(resolver.dumpedAt) < resolver.missRefresh {
		return false
	}
	if !resolver.refreshAt.IsZero() && now.Before(resolver.refreshAt) && resolver.refreshAt.Sub(now) > resolver.ttl {
		// Inside a failure back-off window; do not hammer netlink.
		return false
	}
	entries, err := resolver.dump()
	if err != nil {
		resolver.table = nil
		resolver.dumpedAt = time.Time{}
		resolver.refreshAt = now.Add(resolver.ttl * 10)
		return false
	}
	resolver.dumpedAt = now
	resolver.refreshAt = now.Add(resolver.ttl)
	resolver.table = buildTable(entries)
	return true
}

func (resolver *Resolver) refreshLocked() {
	now := resolver.now()
	if !resolver.refreshAt.IsZero() && now.Before(resolver.refreshAt) {
		return
	}
	entries, err := resolver.dump()
	if err != nil {
		// A previous mapping is not proof after a failed refresh. In
		// particular, reusing a client port must not inherit that backend.
		resolver.table = nil
		resolver.dumpedAt = time.Time{}
		resolver.refreshAt = now.Add(resolver.ttl * 10)
		return
	}
	resolver.dumpedAt = now
	resolver.refreshAt = now.Add(resolver.ttl)
	resolver.table = buildTable(entries)
}

func buildTable(entries []Entry) map[lookupKey]flow.Endpoint {
	table := make(map[lookupKey]flow.Endpoint, len(entries))
	seen := make(map[lookupKey]Tuple, len(entries))
	ambiguous := make(map[lookupKey]bool)
	for _, entry := range entries {
		key := lookupKey{
			protocol:           entry.Original.Protocol,
			sourceAddress:      entry.Original.Source.Address,
			sourcePort:         entry.Original.Source.Port,
			destinationAddress: entry.Original.Destination.Address,
			destinationPort:    entry.Original.Destination.Port,
		}
		// Zones are not part of the socket observation. Conflicting reply
		// tuples therefore cannot be disambiguated, even if one is non-NAT.
		// Keep the tombstone for the whole dump; a later duplicate cannot
		// turn ambiguity back into proof.
		if previous, ok := seen[key]; ok && previous != entry.Reply {
			ambiguous[key] = true
			delete(table, key)
		}
		seen[key] = entry.Reply
		if ambiguous[key] || entry.Reply.Source == entry.Original.Destination {
			continue
		}
		table[key] = entry.Reply.Source
	}
	return table
}

func protocolNumber(protocol string) (uint8, bool) {
	switch protocol {
	case "tcp":
		return protocolNumberTCP, true
	case "udp":
		return protocolNumberUDP, true
	default:
		return 0, false
	}
}

// parseMessages parses one netlink receive buffer that may contain several
// ctnetlink messages. It reports the parsed entries and whether NLMSG_DONE
// was seen.
func parseMessages(data []byte) ([]Entry, bool, error) {
	var entries []Entry
	done := false
	for len(data) >= nlmsgHeaderLength {
		length := int(binary.NativeEndian.Uint32(data[0:4]))
		messageType := binary.NativeEndian.Uint16(data[4:6])
		if length < nlmsgHeaderLength || length > len(data) {
			return nil, false, fmt.Errorf("invalid netlink message length %d", length)
		}
		if binary.NativeEndian.Uint16(data[6:8])&nlmFDumpIntr != 0 {
			return nil, false, fmt.Errorf("interrupted conntrack dump")
		}
		payload := data[nlmsgHeaderLength:length]
		switch messageType {
		case nlmsgDone:
			// Modern kernels put a signed errno in DONE, not only ERROR.
			// A terminator is not proof that the multipart dump succeeded.
			if len(payload) != 0 {
				if len(payload) < 4 {
					return nil, false, fmt.Errorf("short netlink done status")
				}
				if code := int32(binary.NativeEndian.Uint32(payload[:4])); code != 0 {
					return nil, false, fmt.Errorf("netlink dump error %d", code)
				}
			}
			done = true
		case nlmsgError:
			if len(payload) < 4 {
				return nil, false, fmt.Errorf("short netlink error status")
			}
			if code := int32(binary.NativeEndian.Uint32(payload[0:4])); code != 0 {
				return nil, false, fmt.Errorf("netlink error %d", code)
			}
		default:
			if len(payload) > nfgenmsgLength {
				if entry, ok := parseEntry(payload[nfgenmsgLength:]); ok {
					entries = append(entries, entry)
				}
			}
		}
		if align4(length) > len(data) {
			return nil, false, fmt.Errorf("truncated netlink message padding")
		}
		data = data[align4(length):]
	}
	if len(data) != 0 {
		return nil, false, fmt.Errorf("truncated netlink message header")
	}
	return entries, done, nil
}

func parseEntry(data []byte) (Entry, bool) {
	var entry Entry
	var haveOriginal, haveReply bool
	forEachAttribute(data, func(attributeType uint16, value []byte) {
		switch attributeType {
		case ctaTupleOrig:
			if tuple, ok := parseTuple(value); ok {
				entry.Original = tuple
				haveOriginal = true
			}
		case ctaTupleReply:
			if tuple, ok := parseTuple(value); ok {
				entry.Reply = tuple
				haveReply = true
			}
		}
	})
	return entry, haveOriginal && haveReply
}

func parseTuple(data []byte) (Tuple, bool) {
	var tuple Tuple
	var haveAddresses, haveProtocol bool
	forEachAttribute(data, func(attributeType uint16, value []byte) {
		switch attributeType {
		case ctaTupleIP:
			forEachAttribute(value, func(ipType uint16, ipValue []byte) {
				switch ipType {
				case ctaIPv4Src, ctaIPv6Src:
					tuple.Source.Address = formatAddress(ipValue)
				case ctaIPv4Dst, ctaIPv6Dst:
					tuple.Destination.Address = formatAddress(ipValue)
				}
			})
			haveAddresses = tuple.Source.Address != "" && tuple.Destination.Address != ""
		case ctaTupleProto:
			forEachAttribute(value, func(protoType uint16, protoValue []byte) {
				switch protoType {
				case ctaProtoNum:
					if len(protoValue) >= 1 {
						tuple.Protocol = protoValue[0]
						haveProtocol = true
					}
				case ctaProtoSrcPort:
					if len(protoValue) >= 2 {
						tuple.Source.Port = binary.BigEndian.Uint16(protoValue[0:2])
					}
				case ctaProtoDstPort:
					if len(protoValue) >= 2 {
						tuple.Destination.Port = binary.BigEndian.Uint16(protoValue[0:2])
					}
				}
			})
		}
	})
	return tuple, haveAddresses && haveProtocol
}

func forEachAttribute(data []byte, visit func(attributeType uint16, value []byte)) {
	for len(data) >= 4 {
		length := int(binary.NativeEndian.Uint16(data[0:2]))
		attributeType := binary.NativeEndian.Uint16(data[2:4]) & nlaTypeMask
		if length < 4 || length > len(data) {
			return
		}
		visit(attributeType, data[4:length])
		data = data[align4(length):]
	}
}

func formatAddress(value []byte) string {
	switch len(value) {
	case 4, 16:
		return net.IP(value).String()
	default:
		return ""
	}
}

func align4(value int) int {
	return (value + 3) &^ 3
}
