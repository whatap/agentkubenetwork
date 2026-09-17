package tagcount

import (
	"bytes"
	"encoding/hex"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/dns"
	"github.com/whatap/agentkubenetwork/internal/flow"
	"github.com/whatap/agentkubenetwork/internal/l7"
	"github.com/whatap/golib/lang/pack"
	"github.com/whatap/golib/lang/value"
)

func eventHTTP() l7.Transaction {
	return l7.Transaction{
		SchemaVersion: l7.SchemaVersion,
		ObservedAt:    time.Unix(1720000000, 123456789),
		Flow: flow.FlowKey{NodeName: "node-a", Protocol: "tcp", Direction: "client-to-server",
			Source:      flow.Endpoint{Address: "10.0.0.1", Port: 41000},
			Destination: flow.Endpoint{Address: "2001:db8::2", Port: 8080}},
		Protocol: l7.ProtocolHTTP1, Source: l7.SourceKernelPlaintext,
		Method: "GET", StatusCode: 200, ResponseLatencyMicros: 731,
		LatencyBoundary: l7.BoundaryResponseStatus,
	}
}

func assertEventMaps(t *testing.T, p *pack.TagCountPack, tags map[string]string, data map[string]int64) {
	t.Helper()
	if p == nil || p.Tags == nil || p.Data == nil {
		t.Fatal("nil pack/maps")
	}
	id := p.Tags.GetString("record_id")
	raw, err := hex.DecodeString(id)
	if err != nil || len(raw) != 32 {
		t.Fatalf("record_id must be SHA256 hex: %q", id)
	}
	if p.Tags.Size() != len(tags)+1 || p.Data.Size() != len(data) {
		t.Fatalf("unexpected scalar allowlist: tags=%v data=%v", p.Tags, p.Data)
	}
	for k, want := range tags {
		got, ok := p.Tags.Get(k).(*value.TextValue)
		if !ok || got.Val != want {
			t.Errorf("tag %s: got %v want %q", k, p.Tags.Get(k), want)
		}
	}
	for k, want := range data {
		got, ok := p.Data.Get(k).(*value.DecimalValue)
		if !ok || got.Val != want {
			t.Errorf("data %s: got %v want %d", k, p.Data.Get(k), want)
		}
	}
}

func eventRoundTrip(t *testing.T, p *pack.TagCountPack) *pack.TagCountPack {
	t.Helper()
	wire := pack.ToBytesPack(p)
	decoded, ok := pack.ToPack(wire).(*pack.TagCountPack)
	if !ok {
		t.Fatal("not a production TagCountPack wire record")
	}
	if decoded.GetPackType() != pack.TAG_COUNT || decoded.Pcode != p.Pcode || decoded.Oid != p.Oid || decoded.Time != p.Time || decoded.Category != p.Category || decoded.Onode != 0 || decoded.Okind != 0 {
		t.Fatal("envelope changed on wire")
	}
	if !bytes.Equal(wire, pack.ToBytesPack(decoded)) {
		t.Fatal("unstable codec roundtrip")
	}
	return decoded
}

func TestPackForL7ObserverAndTupleIdentity(t *testing.T) {
	tx := eventHTTP()
	tx.Protocol, tx.StreamID, tx.ObserverPID = l7.ProtocolHTTP2, 7, 42
	tx.LatencyBoundary = l7.BoundaryResponseHeaders
	tx.Path = "/private-path?secret-query=secret-value"
	tx.Process = &flow.Process{PID: 42, StartTimeTicks: 987, ContainerID: "server-observer-container",
		Comm: "private-comm", Cmdline: "private-command-line", Via: "private-process-via"}
	tx.SourceResolved = &flow.ResolvedEndpoint{Address: "10.1.0.1", Port: 51000, Via: "conntrack"}
	tx.DestinationResolved = &flow.ResolvedEndpoint{Address: "2001:db8::3", Port: 8443, Via: "conntrack"}
	p, err := PackForL7(tx, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	tags := map[string]string{"schema": l7.SchemaVersion, "observer_node": "node-a", "protocol": "http2",
		"source": "kernel_plaintext", "src_addr": "10.0.0.1", "dst_addr": "2001:db8::2",
		"http_method": "GET", "latency_boundary": l7.BoundaryResponseHeaders,
		"observer_container_id": "server-observer-container", "src_resolved_addr": "10.1.0.1",
		"src_resolution_via": "conntrack", "dst_resolved_addr": "2001:db8::3", "dst_resolution_via": "conntrack"}
	data := map[string]int64{"src_port": 41000, "dst_port": 8080, "observed_at_ms": tx.ObservedAt.UnixMilli(),
		"http_status": 200, "latency_us": 731, "transaction_count": 1, "observer_pid": 42,
		"src_resolved_port": 51000, "dst_resolved_port": 8443, "stream_id": 7}
	assertEventMaps(t, p, tags, data)
	assertEventMaps(t, eventRoundTrip(t, p), tags, data)
	wire := pack.ToBytesPack(p)
	for _, secret := range []string{tx.Path, "secret-query", "private-path", tx.Process.Comm, tx.Process.Cmdline, tx.Process.Via} {
		if bytes.Contains(wire, []byte(secret)) {
			t.Fatalf("private field leaked: %q", secret)
		}
	}
	second, err := PackForL7(tx, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	assertEventIndependent(t, p, second)
	tx.Process.ContainerID = "changed-input"
	tx.SourceResolved.Address, tx.SourceResolved.Port = "10.2.0.1", 1234
	tx.DestinationResolved.Via = "changed-via"
	p.Tags.Get("observer_container_id").(*value.TextValue).Val = "changed-output"
	p.Data.Get("src_resolved_port").(*value.DecimalValue).Val = 1234
	assertEventMaps(t, second, tags, data)
}

func assertEventIndependent(t *testing.T, first, second *pack.TagCountPack) {
	t.Helper()
	if first == second || first.Tags == second.Tags || first.Data == second.Data || first.Tags == first.Data {
		t.Fatal("aliased pack/maps")
	}
	for _, maps := range [][2]*value.MapValue{{first.Tags, second.Tags}, {first.Data, second.Data}} {
		keys := maps[0].Keys()
		for keys.HasMoreElements() {
			k := keys.NextString()
			if maps[0].Get(k) == maps[1].Get(k) {
				t.Fatalf("aliased scalar %s", k)
			}
		}
	}
}

func TestPackForL7ObserverPIDFallback(t *testing.T) {
	tx := eventHTTP()
	tx.Process = &flow.Process{PID: 71}
	p, err := PackForL7(tx, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Data.GetLong("observer_pid") != 71 || p.Tags.ContainsKey("observer_container_id") {
		t.Fatal("known observer PID lost or unknown container invented")
	}
}

func TestPackForL7RecordIdentity(t *testing.T) {
	tx := eventHTTP()
	tx.Protocol, tx.StreamID, tx.ObserverPID = l7.ProtocolHTTP2, 1, 42
	tx.LatencyBoundary = l7.BoundaryResponseHeaders
	tx.Process = &flow.Process{PID: 42, StartTimeTicks: 987, ContainerID: "observer-container"}
	build := func(tx l7.Transaction) *pack.TagCountPack {
		p, err := PackForL7(tx, 1, 1)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	base := build(tx)
	if len(base.Tags.GetString("record_id")) != 64 {
		t.Fatal("missing SHA256 record identity")
	}
	for name, change := range map[string]func(*l7.Transaction){
		"sub-millisecond": func(x *l7.Transaction) { x.ObservedAt = x.ObservedAt.Add(time.Nanosecond) },
		"stream":          func(x *l7.Transaction) { x.StreamID++ },
		"observer":        func(x *l7.Transaction) { x.ObserverPID++; x.Process.PID++ },
		"process reuse":   func(x *l7.Transaction) { x.Process.StartTimeTicks++ },
		"client port":     func(x *l7.Transaction) { x.Flow.Source.Port++ },
		"server address":  func(x *l7.Transaction) { x.Flow.Destination.Address = "2001:db8::3" },
		"latency":         func(x *l7.Transaction) { x.ResponseLatencyMicros++ },
		"status":          func(x *l7.Transaction) { x.StatusCode = 503 },
	} {
		t.Run(name, func(t *testing.T) {
			other := tx
			process := *tx.Process
			other.Process = &process
			change(&other)
			p := build(other)
			if p.Time != base.Time || p.Tags.GetString("record_id") == base.Tags.GetString("record_id") {
				t.Fatal("distinct observation coalesced in same millisecond")
			}
		})
	}
	tx.Path = "/private-new-path?query=private-query"
	tx.Process.Comm, tx.Process.Cmdline, tx.Process.Via = "private-comm", "private-command-line", "private-via"
	tx.ObservedAt = tx.ObservedAt.In(time.FixedZone("same-instant", 3600))
	if got := build(tx).Tags.GetString("record_id"); got != base.Tags.GetString("record_id") {
		t.Fatal("private fields or timezone affected canonical record identity")
	}
}

func TestPackForL7RejectsMalformed(t *testing.T) {
	cases := map[string]func(*l7.Transaction){
		"schema":                         func(x *l7.Transaction) { x.SchemaVersion = "network.l7/v2" },
		"missing schema":                 func(x *l7.Transaction) { x.SchemaVersion = "" },
		"zero time":                      func(x *l7.Transaction) { x.ObservedAt = time.Time{} },
		"epoch":                          func(x *l7.Transaction) { x.ObservedAt = time.Unix(0, 0) },
		"negative time":                  func(x *l7.Transaction) { x.ObservedAt = time.Unix(-1, 0) },
		"millisecond overflow":           func(x *l7.Transaction) { x.ObservedAt = time.Unix(math.MaxInt64/1000+1, 0) },
		"millisecond remainder overflow": func(x *l7.Transaction) { x.ObservedAt = time.Unix(math.MaxInt64/1000, 808000000) },
		"node missing":                   func(x *l7.Transaction) { x.Flow.NodeName = "" },
		"node length":                    func(x *l7.Transaction) { x.Flow.NodeName = strings.Repeat("n", 254) },
		"node whitespace":                func(x *l7.Transaction) { x.Flow.NodeName = "bad node" },
		"node unicode":                   func(x *l7.Transaction) { x.Flow.NodeName = "노드" },
		"node control":                   func(x *l7.Transaction) { x.Flow.NodeName = "node\x7f" },
		"protocol":                       func(x *l7.Transaction) { x.Protocol = "http3" },
		"transport":                      func(x *l7.Transaction) { x.Flow.Protocol = "udp" },
		"direction":                      func(x *l7.Transaction) { x.Flow.Direction = "server-to-client" },
		"source":                         func(x *l7.Transaction) { x.Source = "invented-source" },
		"method":                         func(x *l7.Transaction) { x.Method = "GET /private" },
		"boundary":                       func(x *l7.Transaction) { x.LatencyBoundary = "full-response-body" },
		"status low":                     func(x *l7.Transaction) { x.StatusCode = 0 },
		"status high":                    func(x *l7.Transaction) { x.StatusCode = 600 },
		"latency overflow":               func(x *l7.Transaction) { x.ResponseLatencyMicros = uint64(math.MaxInt64) + 1 },
		"source address missing":         func(x *l7.Transaction) { x.Flow.Source.Address = "" },
		"source wildcard":                func(x *l7.Transaction) { x.Flow.Source.Address = "0.0.0.0" },
		"destination wildcard":           func(x *l7.Transaction) { x.Flow.Destination.Address = "::" },
		"multicast":                      func(x *l7.Transaction) { x.Flow.Destination.Address = "ff02::1" },
		"hostname":                       func(x *l7.Transaction) { x.Flow.Source.Address = "localhost" },
		"zoned address":                  func(x *l7.Transaction) { x.Flow.Source.Address = "fe80::1%en0" },
		"source port":                    func(x *l7.Transaction) { x.Flow.Source.Port = 0 },
		"destination port":               func(x *l7.Transaction) { x.Flow.Destination.Port = 0 },
		"PID mismatch": func(x *l7.Transaction) {
			x.ObserverPID = 42
			x.Process = &flow.Process{PID: 99, ContainerID: "wrong-process"}
		},
		"container control":   func(x *l7.Transaction) { x.Process = &flow.Process{ContainerID: "bad\ncontainer"} },
		"container length":    func(x *l7.Transaction) { x.Process = &flow.Process{ContainerID: strings.Repeat("a", 129)} },
		"resolved incomplete": func(x *l7.Transaction) { x.SourceResolved = &flow.ResolvedEndpoint{} },
		"resolved wildcard": func(x *l7.Transaction) {
			x.SourceResolved = &flow.ResolvedEndpoint{Address: "0.0.0.0", Port: 42, Via: "conntrack"}
		},
		"resolved port": func(x *l7.Transaction) {
			x.DestinationResolved = &flow.ResolvedEndpoint{Address: "10.1.0.1", Via: "conntrack"}
		},
		"resolved provenance": func(x *l7.Transaction) {
			x.SourceResolved = &flow.ResolvedEndpoint{Address: "10.1.0.1", Port: 42, Via: "bad/via"}
		},
		"resolved missing provenance": func(x *l7.Transaction) { x.SourceResolved = &flow.ResolvedEndpoint{Address: "10.1.0.1", Port: 42} },
		"resolved long provenance": func(x *l7.Transaction) {
			x.SourceResolved = &flow.ResolvedEndpoint{Address: "10.1.0.1", Port: 42, Via: strings.Repeat("a", 33)}
		},
		"http1 stream":              func(x *l7.Transaction) { x.StreamID = 1 },
		"http2 stream reserved bit": func(x *l7.Transaction) { x.Protocol = l7.ProtocolHTTP2; x.StreamID = 1 << 31 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			tx := eventHTTP()
			change(&tx)
			p, err := PackForL7(tx, 1, 1)
			if err == nil || p != nil {
				t.Fatal("accepted malformed HTTP observation")
			}
		})
	}
	for _, envelope := range [][2]int64{{0, 1}, {-1, 1}, {1, 0}} {
		p, err := PackForL7(eventHTTP(), envelope[0], int32(envelope[1]))
		if err == nil || p != nil {
			t.Fatal("accepted invalid envelope")
		}
	}
}

func TestPackForL7AcceptsNumericBoundsAndUnknownIdentity(t *testing.T) {
	for _, latency := range []uint64{0, math.MaxInt64} {
		tx := eventHTTP()
		tx.ResponseLatencyMicros = latency
		tx.ObservedAt = time.Unix(math.MaxInt64/1000, 807999999)
		tx.Process = &flow.Process{}
		p, err := PackForL7(tx, math.MaxInt64, math.MinInt32)
		if err != nil {
			t.Fatal(err)
		}
		p = eventRoundTrip(t, p)
		if p.Time != math.MaxInt64 || p.Data.GetLong("latency_us") != int64(latency) {
			t.Fatal("int64 boundary lost")
		}
		for _, key := range []string{"observer_pid", "observer_container_id", "stream_id", "src_pod_uid", "dst_pod_uid"} {
			if p.Tags.ContainsKey(key) || p.Data.ContainsKey(key) {
				t.Fatalf("invented optional identity: %s", key)
			}
		}
	}
}

func eventDNS() dns.Transaction {
	return dns.Transaction{SchemaVersion: dns.SchemaVersion, ObservedAt: time.Unix(1720000000, 123456789),
		NodeName: "node-a", Protocol: "udp", Client: flow.Endpoint{Address: "10.0.0.1", Port: 41000},
		Server: flow.Endpoint{Address: "10.96.0.10", Port: 53}, QueryName: "api.default.svc.cluster.local",
		QueryType: "A", Outcome: dns.OutcomeResponse, ResponseCode: "NOERROR", LatencyMeasured: true, LatencyMicros: 812}
}

func TestPackForDNSResponseWireObservation(t *testing.T) {
	for _, code := range []string{"NOERROR", "NXDOMAIN", "SERVFAIL"} {
		for _, latency := range []uint64{0, 812, math.MaxInt64} {
			tx := eventDNS()
			tx.ResponseCode, tx.LatencyMicros = code, latency
			p, err := PackForDNS(tx, math.MaxInt64, math.MinInt32)
			if err != nil {
				t.Fatal(err)
			}
			if DNSCategory != "kube_network_dns_v1alpha1" || p.Category != DNSCategory || p.Time != tx.ObservedAt.UnixMilli() || p.Pcode != math.MaxInt64 || p.Oid != math.MinInt32 {
				t.Fatal("wrong DNS envelope")
			}
			tags := map[string]string{"schema": dns.SchemaVersion, "observer_node": "node-a", "protocol": "udp",
				"client_addr": "10.0.0.1", "server_addr": "10.96.0.10", "query_name": tx.QueryName,
				"query_type": "A", "outcome": dns.OutcomeResponse, "rcode": code}
			data := map[string]int64{"client_port": 41000, "server_port": 53, "observed_at_ms": tx.ObservedAt.UnixMilli(),
				"transaction_count": 1, "response_count": 1, "latency_us": int64(latency)}
			assertEventMaps(t, p, tags, data)
			assertEventMaps(t, eventRoundTrip(t, p), tags, data)
		}
	}
}

func TestPackForDNSMissingResponseIsNotZeroLatency(t *testing.T) {
	for _, tc := range []struct{ outcome, reason string }{
		{dns.OutcomeNoResponse, ""}, {dns.OutcomeParseError, ""},
		{dns.OutcomeIncomplete, dns.ReasonCaptureEnded}, {dns.OutcomeIncomplete, dns.ReasonStateCapacity},
	} {
		t.Run(tc.outcome+tc.reason, func(t *testing.T) {
			tx := eventDNS()
			tx.Client.Address = "0.0.0.0" // an unknown observed bind address, not a Pod
			tx.Outcome, tx.Reason, tx.ResponseCode, tx.LatencyMicros = tc.outcome, tc.reason, "", 0
			tx.LatencyMeasured = false
			if tc.outcome == dns.OutcomeParseError {
				tx.QueryName, tx.QueryType = "", ""
			}
			p, err := PackForDNS(tx, 1, -1)
			if err != nil {
				t.Fatal(err)
			}
			tags := map[string]string{"schema": dns.SchemaVersion, "observer_node": "node-a", "protocol": "udp",
				"client_addr": "0.0.0.0", "server_addr": "10.96.0.10", "outcome": tc.outcome}
			if tx.QueryName != "" {
				tags["query_name"] = tx.QueryName
			}
			if tx.QueryType != "" {
				tags["query_type"] = tx.QueryType
			}
			if tc.reason != "" {
				tags["reason"] = tc.reason
			}
			data := map[string]int64{"client_port": 41000, "server_port": 53,
				"observed_at_ms": tx.ObservedAt.UnixMilli(), "transaction_count": 1, "response_count": 0}
			assertEventMaps(t, p, tags, data)
			assertEventMaps(t, eventRoundTrip(t, p), tags, data)
			if p.Data.ContainsKey("latency_us") || p.Tags.ContainsKey("rcode") {
				t.Fatal("invented latency or NOERROR")
			}
		})
	}
}

func TestPackForDNSResponseWithoutCodeRemainsUnknown(t *testing.T) {
	tx := eventDNS()
	tx.ResponseCode, tx.QueryName, tx.QueryType = "", "", ""
	p, err := PackForDNS(tx, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	p = eventRoundTrip(t, p)
	for _, k := range []string{"rcode", "reason", "query_name", "query_type"} {
		if p.Tags.ContainsKey(k) {
			t.Fatalf("invented optional DNS metadata: %s", k)
		}
	}
	if p.Data.GetLong("response_count") != 1 || !p.Data.ContainsKey("latency_us") {
		t.Fatal("lost response sample")
	}
}

func TestPackForL7WireObservation(t *testing.T) {
	for _, protocol := range []string{l7.ProtocolHTTP1, l7.ProtocolHTTP2} {
		for _, source := range []l7.Source{l7.SourceKernelPlaintext, l7.SourceOpenSSL} {
			tx := eventHTTP()
			tx.Protocol, tx.Source = protocol, source
			if protocol == l7.ProtocolHTTP2 {
				tx.LatencyBoundary, tx.StreamID = l7.BoundaryResponseHeaders, 1
			}
			p, err := PackForL7(tx, 9876543210, -42)
			if err != nil {
				t.Fatal(err)
			}
			if HTTPCategory != "kube_network_http_v1alpha1" || p.Category != HTTPCategory || p.Pcode != 9876543210 || p.Oid != -42 || p.Time != tx.ObservedAt.UnixMilli() {
				t.Fatal("wrong HTTP envelope")
			}
			tags := map[string]string{"schema": l7.SchemaVersion, "observer_node": "node-a", "protocol": protocol,
				"source": string(source), "src_addr": "10.0.0.1", "dst_addr": "2001:db8::2",
				"http_method": "GET", "latency_boundary": tx.LatencyBoundary}
			data := map[string]int64{"src_port": 41000, "dst_port": 8080, "observed_at_ms": tx.ObservedAt.UnixMilli(),
				"http_status": 200, "latency_us": 731, "transaction_count": 1}
			if tx.StreamID != 0 {
				data["stream_id"] = int64(tx.StreamID)
			}
			assertEventMaps(t, p, tags, data)
			assertEventMaps(t, eventRoundTrip(t, p), tags, data)
		}
	}
}
