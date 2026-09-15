package conntrack

import (
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
)

func attribute(attributeType uint16, value []byte) []byte {
	length := 4 + len(value)
	data := make([]byte, align4(length))
	binary.NativeEndian.PutUint16(data[0:2], uint16(length))
	binary.NativeEndian.PutUint16(data[2:4], attributeType)
	copy(data[4:], value)
	return data
}

func port(value uint16) []byte {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, value)
	return data
}

func tupleAttribute(tupleType uint16, protocol uint8, source, destination flow.Endpoint) []byte {
	proto := append(
		attribute(ctaProtoNum, []byte{protocol}),
		append(attribute(ctaProtoSrcPort, port(source.Port)), attribute(ctaProtoDstPort, port(destination.Port))...)...,
	)
	ipValue := append(
		attribute(ctaIPv4Src, ipv4Bytes(source.Address)),
		attribute(ctaIPv4Dst, ipv4Bytes(destination.Address))...,
	)
	return attribute(tupleType, append(attribute(ctaTupleIP, ipValue), attribute(ctaTupleProto, proto)...))
}

func ipv4Bytes(address string) []byte {
	var a, b, c, d int
	if n, err := sscanf4(address, &a, &b, &c, &d); n != 4 || err != nil {
		panic("invalid test address " + address)
	}
	return []byte{byte(a), byte(b), byte(c), byte(d)}
}

func sscanf4(address string, parts ...*int) (int, error) {
	count := 0
	value := 0
	seen := false
	for i := 0; i <= len(address); i++ {
		if i == len(address) || address[i] == '.' {
			if !seen || count >= len(parts) {
				return count, errors.New("malformed address")
			}
			*parts[count] = value
			count++
			value = 0
			seen = false
			continue
		}
		if address[i] < '0' || address[i] > '9' {
			return count, errors.New("malformed address")
		}
		value = value*10 + int(address[i]-'0')
		seen = true
	}
	return count, nil
}

func netlinkMessage(messageType uint16, payload []byte) []byte {
	length := nlmsgHeaderLength + len(payload)
	data := make([]byte, align4(length))
	binary.NativeEndian.PutUint32(data[0:4], uint32(length))
	binary.NativeEndian.PutUint16(data[4:6], messageType)
	copy(data[nlmsgHeaderLength:], payload)
	return data
}

func conntrackMessage(entryPayload []byte) []byte {
	payload := append(make([]byte, nfgenmsgLength), entryPayload...)
	return netlinkMessage(nfnlCtNewType, payload)
}

const nfnlCtNewType = 1<<8 | 0 // NFNL_SUBSYS_CTNETLINK << 8 | IPCTNL_MSG_CT_NEW

func dnatEntryBytes() []byte {
	original := tupleAttribute(ctaTupleOrig, protocolNumberTCP,
		flow.Endpoint{Address: "10.131.1.173", Port: 41000},
		flow.Endpoint{Address: "172.30.181.224", Port: 8080},
	)
	reply := tupleAttribute(ctaTupleReply, protocolNumberTCP,
		flow.Endpoint{Address: "10.128.3.88", Port: 8080},
		flow.Endpoint{Address: "10.131.1.173", Port: 41000},
	)
	return append(original, reply...)
}

func TestParseMessagesDecodesDNATEntry(t *testing.T) {
	data := append(conntrackMessage(dnatEntryBytes()), netlinkMessage(nlmsgDone, nil)...)

	entries, done, err := parseMessages(data)
	if err != nil {
		t.Fatalf("parseMessages returned error: %v", err)
	}
	if !done {
		t.Fatal("expected NLMSG_DONE to be reported")
	}
	if len(entries) != 1 {
		t.Fatalf("expected one entry, got %d", len(entries))
	}
	entry := entries[0]
	if entry.Original.Protocol != protocolNumberTCP ||
		entry.Original.Source != (flow.Endpoint{Address: "10.131.1.173", Port: 41000}) ||
		entry.Original.Destination != (flow.Endpoint{Address: "172.30.181.224", Port: 8080}) {
		t.Fatalf("unexpected original tuple: %+v", entry.Original)
	}
	if entry.Reply.Source != (flow.Endpoint{Address: "10.128.3.88", Port: 8080}) {
		t.Fatalf("unexpected reply tuple: %+v", entry.Reply)
	}
}

func TestParseMessagesReportsNetlinkError(t *testing.T) {
	payload := make([]byte, 4)
	binary.NativeEndian.PutUint32(payload, uint32(0xffffffff)) // -1
	if _, _, err := parseMessages(netlinkMessage(nlmsgError, payload)); err == nil {
		t.Fatal("expected netlink error to surface")
	}
}

func TestResolverResolvesOnlyRewrittenDestinations(t *testing.T) {
	entries := []Entry{
		{
			Original: Tuple{
				Protocol:    protocolNumberTCP,
				Source:      flow.Endpoint{Address: "10.131.1.173", Port: 41000},
				Destination: flow.Endpoint{Address: "172.30.181.224", Port: 8080},
			},
			Reply: Tuple{
				Protocol:    protocolNumberTCP,
				Source:      flow.Endpoint{Address: "10.128.3.88", Port: 8080},
				Destination: flow.Endpoint{Address: "10.131.1.173", Port: 41000},
			},
		},
		{
			// No NAT: reply source equals original destination.
			Original: Tuple{
				Protocol:    protocolNumberTCP,
				Source:      flow.Endpoint{Address: "10.0.0.1", Port: 1000},
				Destination: flow.Endpoint{Address: "10.0.0.2", Port: 80},
			},
			Reply: Tuple{
				Protocol:    protocolNumberTCP,
				Source:      flow.Endpoint{Address: "10.0.0.2", Port: 80},
				Destination: flow.Endpoint{Address: "10.0.0.1", Port: 1000},
			},
		},
	}
	resolver := newResolver(func() ([]Entry, error) { return entries, nil }, time.Second, time.Now)

	resolved, via, ok := resolver.Resolve("tcp",
		flow.Endpoint{Address: "10.131.1.173", Port: 41000},
		flow.Endpoint{Address: "172.30.181.224", Port: 8080},
	)
	if !ok || via != Via || resolved != (flow.Endpoint{Address: "10.128.3.88", Port: 8080}) {
		t.Fatalf("unexpected resolution: %v %q %v", resolved, via, ok)
	}

	if _, _, ok := resolver.Resolve("tcp",
		flow.Endpoint{Address: "10.0.0.1", Port: 1000},
		flow.Endpoint{Address: "10.0.0.2", Port: 80},
	); ok {
		t.Fatal("non-NAT flow must not resolve")
	}
	if _, _, ok := resolver.Resolve("icmp", flow.Endpoint{}, flow.Endpoint{}); ok {
		t.Fatal("unsupported protocol must not resolve")
	}
}

func TestResolverRefreshesOnMissForNewConnections(t *testing.T) {
	current := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	client := flow.Endpoint{Address: "10.131.1.173", Port: 41924}
	service := flow.Endpoint{Address: "172.30.181.224", Port: 8080}
	backend := flow.Endpoint{Address: "10.128.2.74", Port: 8080}
	var entries []Entry
	dumps := 0
	resolver := newResolver(func() ([]Entry, error) {
		dumps++
		return entries, nil
	}, time.Second, func() time.Time { return current })

	// Initial dump: table is empty, connection does not exist yet.
	if _, _, ok := resolver.Resolve("tcp", client, service); ok || dumps != 1 {
		t.Fatalf("expected miss with one dump, ok=%v dumps=%d", ok, dumps)
	}

	// Kernel creates the DNAT entry 30ms later; a miss inside the TTL window
	// must trigger a fresh dump instead of waiting for the next scheduled one.
	entries = []Entry{{
		Original: Tuple{Protocol: protocolNumberTCP, Source: client, Destination: service},
		Reply:    Tuple{Protocol: protocolNumberTCP, Source: backend, Destination: client},
	}}
	current = current.Add(30 * time.Millisecond)
	resolved, via, ok := resolver.Resolve("tcp", client, service)
	if !ok || via != Via || resolved != backend || dumps != 2 {
		t.Fatalf("expected miss-triggered refresh to resolve backend, got %+v ok=%v dumps=%d", resolved, ok, dumps)
	}

	// Repeated misses within missRefresh do not dump again.
	current = current.Add(5 * time.Millisecond)
	resolver.Resolve("tcp", flow.Endpoint{Address: "10.131.1.173", Port: 1}, service)
	if dumps != 2 {
		t.Fatalf("expected miss refresh to be rate limited, got %d dumps", dumps)
	}
}

func TestResolverCachesDumpsAndBacksOffOnError(t *testing.T) {
	current := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	dumps := 0
	failing := false
	resolver := newResolver(func() ([]Entry, error) {
		dumps++
		if failing {
			return nil, errors.New("dump failed")
		}
		return nil, nil
	}, time.Second, func() time.Time { return current })

	resolver.Resolve("tcp", flow.Endpoint{}, flow.Endpoint{})
	resolver.Resolve("tcp", flow.Endpoint{}, flow.Endpoint{})
	if dumps != 1 {
		t.Fatalf("expected one dump within ttl, got %d", dumps)
	}

	current = current.Add(2 * time.Second)
	failing = true
	resolver.Resolve("tcp", flow.Endpoint{}, flow.Endpoint{})
	if dumps != 2 {
		t.Fatalf("expected refresh after ttl, got %d dumps", dumps)
	}
	current = current.Add(5 * time.Second)
	resolver.Resolve("tcp", flow.Endpoint{}, flow.Endpoint{})
	if dumps != 2 {
		t.Fatalf("expected error backoff to suppress dumps, got %d", dumps)
	}
	current = current.Add(10 * time.Second)
	resolver.Resolve("tcp", flow.Endpoint{}, flow.Endpoint{})
	if dumps != 3 {
		t.Fatalf("expected retry after backoff, got %d dumps", dumps)
	}
}
