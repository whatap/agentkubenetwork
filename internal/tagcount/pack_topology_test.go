package tagcount

import (
	"bytes"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/l7"
	"github.com/whatap/agentkubenetwork/internal/topology"
	"github.com/whatap/golib/lang/pack"
	"github.com/whatap/golib/lang/value"
)

func topologyTestSummary() topology.Summary {
	start := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	return topology.Summary{
		ClusterID: "cluster-a", WindowStart: start, WindowEnd: start.Add(5 * time.Second),
		Source:      topology.Endpoint{Kind: "Deployment", UID: "frontend-uid", Name: "frontend", Namespace: "apps"},
		Destination: topology.Endpoint{Kind: "StatefulSet", UID: "backend-uid", Name: "backend", Namespace: "data"},
		Transport:   "tcp", Protocol: "tcp", Direction: topology.DirectionUnknown,
		Observed: true, LastSeenMS: start.Add(time.Second).UnixMilli(),
	}
}

func assertTopologyPack(t *testing.T, p *pack.TagCountPack, s topology.Summary) {
	t.Helper()
	if p == nil || p.Tags == nil || p.Data == nil {
		t.Fatal("nil topology pack or maps")
	}
	if TopologyCategory != "kube_network_topology_v1alpha1" || p.Category != TopologyCategory {
		t.Fatalf("incorrect topology category: %q", p.Category)
	}
	if p.Time != s.WindowStart.UnixMilli() || p.Onode != 0 || p.Okind != 0 {
		t.Fatal("topology envelope must use bucket start, without observer identity")
	}
	tags := map[string]string{
		"schema": "network.topology/v1alpha1", "cluster_id": s.ClusterID,
		"transport": s.Transport, "protocol": s.Protocol, "direction": s.Direction,
	}
	for _, endpoint := range []struct {
		prefix string
		value  topology.Endpoint
	}{{"src", s.Source}, {"dst", s.Destination}} {
		tags[endpoint.prefix+"_kind"] = endpoint.value.Kind
		if endpoint.value.Kind == topology.KindUnresolvedAddress {
			tags[endpoint.prefix+"_address"] = endpoint.value.Address
		} else {
			tags[endpoint.prefix+"_uid"] = endpoint.value.UID
			tags[endpoint.prefix+"_name"] = endpoint.value.Name
			tags[endpoint.prefix+"_namespace"] = endpoint.value.Namespace
		}
	}
	// Only a confirmed server port belongs in the relationship's tag key.
	if s.DestinationPort != 0 {
		port := value.NewDecimalValue(int64(s.DestinationPort))
		tags["dst_port"] = port.String()
	}
	fields := map[string]int64{
		"observed": 0, "result_observed": 0, "error_observed": 0,
		"last_seen_ms": s.LastSeenMS, "window_start_ms": s.WindowStart.UnixMilli(), "window_end_ms": s.WindowEnd.UnixMilli(),
	}
	if s.Observed {
		fields["observed"] = 1
	}
	if s.ResultObserved {
		fields["result_observed"] = 1
	}
	if s.ErrorObserved {
		fields["error_observed"] = 1
	}
	if p.Tags.Size() != len(tags) || p.Data.Size() != len(fields) {
		t.Fatalf("unexpected topology schema: tags=%v fields=%v", p.Tags, p.Data)
	}
	for key, want := range tags {
		got, ok := p.Tags.Get(key).(*value.TextValue)
		if !ok || got.Val != want {
			t.Fatalf("tag %q = %v, want text %q", key, p.Tags.Get(key), want)
		}
	}
	for key, want := range fields {
		got, ok := p.Data.Get(key).(*value.DecimalValue)
		if !ok || got.Val != want {
			t.Fatalf("field %q = %v, want long %d", key, p.Data.Get(key), want)
		}
	}
	for _, key := range []string{
		"observer_node", "observer_pod_uid", "src_pod_uid", "dst_pod_uid", "pod_uid",
		"observer_container_id", "container_id", "observer_pid", "pid", "PID", "record_id",
		"src_port", "path", "http_path", "query_name", "dns_name", "transaction_count", "request_count", "response_count",
	} {
		if p.Tags.ContainsKey(key) || p.Data.ContainsKey(key) {
			t.Fatalf("unexpected observer, high-cardinality or request-count field %q", key)
		}
	}
}

func TestPackForTopologyWireRoundTrip(t *testing.T) {
	cases := map[string]func(*topology.Summary){
		"workloads TCP presence": func(s *topology.Summary) {},
		"unresolved source": func(s *topology.Summary) {
			s.Source = topology.Endpoint{Kind: topology.KindUnresolvedAddress, Address: "10.0.0.1"}
		},
		"unresolved destination": func(s *topology.Summary) {
			s.Destination = topology.Endpoint{Kind: topology.KindUnresolvedAddress, Address: "2001:db8::2"}
		},
		"both unresolved": func(s *topology.Summary) {
			s.Source = topology.Endpoint{Kind: topology.KindUnresolvedAddress, Address: "10.0.0.1"}
			s.Destination = topology.Endpoint{Kind: topology.KindUnresolvedAddress, Address: "2001:db8::2"}
		},
		"HTTP response": func(s *topology.Summary) {
			s.Protocol, s.Direction, s.DestinationPort = l7.ProtocolHTTP1, topology.DirectionRequest, 8080
			s.ResultObserved = true
		},
		"HTTP2 error": func(s *topology.Summary) {
			s.Protocol, s.Direction, s.DestinationPort = l7.ProtocolHTTP2, topology.DirectionRequest, 65535
			s.ResultObserved, s.ErrorObserved = true, true
		},
		"DNS no confirmed response": func(s *topology.Summary) {
			s.Transport, s.Protocol, s.Direction, s.DestinationPort = "udp", "dns", topology.DirectionRequest, 53
		},
		"DNS error response": func(s *topology.Summary) {
			s.Transport, s.Protocol, s.Direction, s.DestinationPort = "udp", "dns", topology.DirectionRequest, 53
			s.ResultObserved, s.ErrorObserved = true, true
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s := topologyTestSummary()
			change(&s)
			before := s
			p, err := PackForTopology(s, 9876543210, -12345)
			if err != nil {
				t.Fatal(err)
			}
			assertTopologyPack(t, p, s)
			wire := pack.ToBytesPack(p)
			decoded, ok := pack.ToPack(wire).(*pack.TagCountPack)
			if !ok {
				t.Fatal("wire is not a TagCountPack")
			}
			if decoded.GetPackType() != pack.TAG_COUNT || decoded.Pcode != 9876543210 || decoded.Oid != -12345 {
				t.Fatal("wire lost trusted pack identity")
			}
			assertTopologyPack(t, decoded, s)
			if !bytes.Equal(pack.ToBytesPack(decoded), wire) || s != before {
				t.Fatal("unstable wire encoding or mutated summary")
			}
		})
	}
}

func TestPackForTopologyIdentityBounds(t *testing.T) {
	for _, identity := range []struct {
		pcode int64
		oid   int32
	}{{1, 1}, {math.MaxInt64, math.MinInt32}, {1, math.MaxInt32}} {
		p, err := PackForTopology(topologyTestSummary(), identity.pcode, identity.oid)
		if err != nil || p == nil || p.Pcode != identity.pcode || p.Oid != identity.oid {
			t.Fatalf("valid identity rejected or changed: %+v, %v", identity, err)
		}
	}
	for _, identity := range []struct {
		pcode int64
		oid   int32
	}{{0, 1}, {-1, 1}, {math.MinInt64, 1}, {1, 0}} {
		if p, err := PackForTopology(topologyTestSummary(), identity.pcode, identity.oid); err == nil || p != nil {
			t.Fatalf("accepted invalid identity: %+v", identity)
		}
	}
}

func TestPackForTopologyRejectsMalformedSummary(t *testing.T) {
	cases := map[string]func(*topology.Summary){
		"empty cluster":              func(s *topology.Summary) { s.ClusterID = "" },
		"cluster whitespace":         func(s *topology.Summary) { s.ClusterID = "cluster a" },
		"cluster too long":           func(s *topology.Summary) { s.ClusterID = strings.Repeat("a", 254) },
		"zero start":                 func(s *topology.Summary) { s.WindowStart = time.Time{} },
		"epoch start":                func(s *topology.Summary) { s.WindowStart = time.UnixMilli(0) },
		"negative start":             func(s *topology.Summary) { s.WindowStart = time.UnixMilli(-1) },
		"empty window":               func(s *topology.Summary) { s.WindowEnd = s.WindowStart },
		"backwards window":           func(s *topology.Summary) { s.WindowEnd = s.WindowStart.Add(-time.Millisecond) },
		"oversized window":           func(s *topology.Summary) { s.WindowEnd = s.WindowStart.Add(time.Minute + time.Millisecond) },
		"overflow time":              func(s *topology.Summary) { s.WindowEnd = time.Unix(math.MaxInt64, 0) },
		"last seen before window":    func(s *topology.Summary) { s.LastSeenMS = s.WindowStart.UnixMilli() - 1 },
		"last seen at exclusive end": func(s *topology.Summary) { s.LastSeenMS = s.WindowEnd.UnixMilli() },
		"missing kind":               func(s *topology.Summary) { s.Source.Kind = "" },
		"missing workload UID":       func(s *topology.Summary) { s.Source.UID = "" },
		"missing workload name":      func(s *topology.Summary) { s.Destination.Name = "" },
		"missing workload namespace": func(s *topology.Summary) { s.Destination.Namespace = "" },
		"workload plus address":      func(s *topology.Summary) { s.Source.Address = "10.0.0.1" },
		"oversized workload kind":    func(s *topology.Summary) { s.Source.Kind = strings.Repeat("x", 64) },
		"oversized workload UID":     func(s *topology.Summary) { s.Source.UID = strings.Repeat("x", 254) },
		"oversized workload name":    func(s *topology.Summary) { s.Source.Name = strings.Repeat("x", 254) },
		"oversized namespace":        func(s *topology.Summary) { s.Source.Namespace = strings.Repeat("x", 64) },
		"workload control byte":      func(s *topology.Summary) { s.Source.Name = "front\nend" },
		"unresolved plus UID": func(s *topology.Summary) {
			s.Source = topology.Endpoint{Kind: topology.KindUnresolvedAddress, Address: "10.0.0.1", UID: "pod-id"}
		},
		"unresolved hostname": func(s *topology.Summary) {
			s.Destination = topology.Endpoint{Kind: topology.KindUnresolvedAddress, Address: "example.test"}
		},
		"unresolved wildcard": func(s *topology.Summary) {
			s.Source = topology.Endpoint{Kind: topology.KindUnresolvedAddress, Address: "0.0.0.0"}
		},
		"unresolved multicast": func(s *topology.Summary) {
			s.Source = topology.Endpoint{Kind: topology.KindUnresolvedAddress, Address: "ff02::1"}
		},
		"unresolved zone": func(s *topology.Summary) {
			s.Source = topology.Endpoint{Kind: topology.KindUnresolvedAddress, Address: "fe80::1%en0"}
		},
		"bad transport":              func(s *topology.Summary) { s.Transport = "icmp" },
		"bad protocol":               func(s *topology.Summary) { s.Protocol = "https://private/path" },
		"bad direction":              func(s *topology.Summary) { s.Direction = "egress" },
		"unconfirmed server port":    func(s *topology.Summary) { s.DestinationPort = 40000 },
		"result without observation": func(s *topology.Summary) { s.Observed, s.ResultObserved = false, true },
		"error without result":       func(s *topology.Summary) { s.ErrorObserved = true },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s := topologyTestSummary()
			change(&s)
			if p, err := PackForTopology(s, 1, 1); err == nil || p != nil {
				t.Fatal("malformed topology summary was serialized")
			}
		})
	}
}

func TestPackForTopologyIndependentSnapshots(t *testing.T) {
	s := topologyTestSummary()
	first, err := PackForTopology(s, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PackForTopology(s, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || first.Tags == second.Tags || first.Data == second.Data || first.Tags == first.Data {
		t.Fatal("topology packs share mutable maps")
	}
	first.Tags.Get("src_uid").(*value.TextValue).Val = "mutated-pack"
	first.Data.Get("observed").(*value.DecimalValue).Val = 99
	assertTopologyPack(t, second, s)
	s.Source.UID, s.ClusterID, s.LastSeenMS = "mutated-input", "other-cluster", 1
	if second.Tags.GetString("src_uid") != "frontend-uid" || second.Tags.GetString("cluster_id") != "cluster-a" || second.Data.GetLong("last_seen_ms") == 1 {
		t.Fatal("input mutation changed a returned topology pack")
	}
}
