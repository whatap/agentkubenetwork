package tagcount

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/whatap/agentkubenetwork/internal/bridge"
	"github.com/whatap/agentkubenetwork/internal/flow"
	"github.com/whatap/golib/lang/pack"
	"github.com/whatap/golib/lang/value"
	"math"
	"os"
	"strings"
	"testing"
	"time"
)

func packTestWindow(t *testing.T) flow.Window {
	t.Helper()
	data, err := os.ReadFile("../bridge/testdata/producer-window.json")
	if err != nil {
		t.Fatal(err)
	}
	var w flow.Window
	if err = json.Unmarshal(data, &w); err != nil {
		t.Fatal(err)
	}
	return w
}

func packTestOptionalWindow(t *testing.T) flow.Window {
	t.Helper()
	w := packTestWindow(t)
	w.Process = &flow.Process{PID: 42, StartTimeTicks: 123, Comm: "synthetic-private-comm", Cmdline: "synthetic-secret-command-line", ContainerID: "observer-container", Via: "synthetic-private-process-via"}
	w.SourceResolved = &flow.ResolvedEndpoint{Address: "10.1.0.1", Port: 2345, Via: "conntrack"}
	w.DestinationResolved = &flow.ResolvedEndpoint{Address: "2001:db8::2", Port: 8443, Via: "conntrack"}
	return w
}

func assertPackMapping(t *testing.T, p *pack.TagCountPack, w flow.Window) {
	t.Helper()
	if p == nil || p.Tags == nil || p.Data == nil {
		t.Fatal("nil pack or maps")
	}
	if Category != "kube_network_edge_v1alpha1" || p.Category != Category {
		t.Fatal("incorrect category")
	}
	role := "unknown"
	if w.Flow.Direction == "egress" {
		role = "source"
	} else if w.Flow.Direction == "ingress" {
		role = "destination"
	}
	tags := map[string]string{
		"schema":        "network.edge.window/v1alpha1",
		"observer_node": w.Flow.NodeName,
		"protocol":      "tcp",
		"src_addr":      w.Flow.Source.Address,
		"dst_addr":      w.Flow.Destination.Address,
		"observer_role": role,
	}
	fields := map[string]int64{
		"src_port":        int64(w.Flow.Source.Port),
		"dst_port":        int64(w.Flow.Destination.Port),
		"window_start_ms": w.WindowStart.UnixMilli(),
		"window_end_ms":   w.WindowEnd.UnixMilli(),
		"srtt_count":      int64(w.RTT.Count),
		"srtt_sum_us":     int64(w.RTT.SumMicros),
		"srtt_min_us":     int64(w.RTT.MinMicros),
		"srtt_max_us":     int64(w.RTT.MaxMicros),
	}
	if w.Process != nil && w.Process.ContainerID != "" {
		tags["observer_container_id"] = w.Process.ContainerID
	}
	for _, resolved := range []struct {
		prefix string
		ep     *flow.ResolvedEndpoint
	}{{"src", w.SourceResolved}, {"dst", w.DestinationResolved}} {
		if resolved.ep != nil {
			tags[resolved.prefix+"_resolved_addr"] = resolved.ep.Address
			tags[resolved.prefix+"_resolution_via"] = resolved.ep.Via
			fields[resolved.prefix+"_resolved_port"] = int64(resolved.ep.Port)
		}
	}
	if p.Tags.Size() != len(tags) || p.Data.Size() != len(fields) {
		t.Fatal("missing or unexpected tag/field")
	}
	for key, want := range tags {
		got, ok := p.Tags.Get(key).(*value.TextValue)
		if !ok || got.Val != want {
			t.Fatalf("incorrect text tag %s", key)
		}
	}
	for key, want := range fields {
		got, ok := p.Data.Get(key).(*value.DecimalValue)
		if !ok || got.Val != want {
			t.Fatalf("incorrect numeric field %s", key)
		}
	}
}

func TestPackForWindowMappings(t *testing.T) {
	cases := map[string]func(*flow.Window){
		"producer fixture": func(w *flow.Window) {},
		"no process":       func(w *flow.Window) { w.Process = nil },
		"container":        func(w *flow.Window) { w.Process.ContainerID = "observer-container" },
		"source NAT": func(w *flow.Window) {
			w.SourceResolved = &flow.ResolvedEndpoint{Address: "10.1.0.1", Port: 2345, Via: "conntrack"}
		},
		"destination NAT": func(w *flow.Window) {
			w.DestinationResolved = &flow.ResolvedEndpoint{Address: "2001:db8::2", Port: 8443, Via: "conntrack"}
		},
		"IPv6 sockets": func(w *flow.Window) {
			w.Flow.Source.Address = "2001:db8::1"
			w.Flow.Destination.Address = "2001:db8::2"
		},
		"multiple samples": func(w *flow.Window) {
			w.RTT = flow.Distribution{Count: 3, SumMicros: 45, MinMicros: 10, MaxMicros: 20}
		},
		"large numeric values": func(w *flow.Window) {
			w.RTT = flow.Distribution{Count: 1, SumMicros: 1<<53 - 1, MinMicros: 1<<53 - 1, MaxMicros: 1<<53 - 1}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			w := packTestWindow(t)
			change(&w)
			p, err := PackForWindow(w, 12345, 6789)
			if err != nil {
				t.Fatal(err)
			}
			assertPackMapping(t, p, w)
		})
	}
}

func TestPackObserverRoles(t *testing.T) {
	for direction, role := range map[string]string{"egress": "source", "ingress": "destination", "connection": "unknown", "": "unknown", "other": "unknown"} {
		t.Run(direction, func(t *testing.T) {
			w := packTestWindow(t)
			w.Flow.Direction = direction
			p, err := PackForWindow(w, 1, 1)
			if err != nil || p.Tags.GetString("observer_role") != role {
				t.Fatal("incorrect observer role", err)
			}
			assertPackMapping(t, p, w)
		})
	}
}

func TestPackTrustedIdentityAndTime(t *testing.T) {
	for _, identity := range []struct {
		pcode int64
		oid   int32
	}{{1, 1}, {2345, -6789}, {math.MaxInt64, math.MinInt32}} {
		w := packTestOptionalWindow(t)
		w.WindowStart = w.WindowStart.Add(123 * time.Microsecond)
		p, err := PackForWindow(w, identity.pcode, identity.oid)
		if err != nil {
			t.Fatal(err)
		}
		if p.Pcode != identity.pcode || p.Oid != identity.oid || p.Time != w.WindowStart.UnixMilli() || p.Onode != 0 || p.Okind != 0 {
			t.Fatal("pack identity/time was derived from untrusted window or current time")
		}
		assertPackMapping(t, p, w)
	}
}

func TestPackWireRoundTrip(t *testing.T) {
	w := packTestOptionalWindow(t)
	w.Flow.Direction = "ingress"
	p, err := PackForWindow(w, 9876543210, -12345)
	if err != nil {
		t.Fatal(err)
	}
	wire := pack.ToBytesPack(p)
	decoded, ok := pack.ToPack(wire).(*pack.TagCountPack)
	if !ok {
		t.Fatal("wire is not a TagCountPack")
	}
	if decoded.GetPackType() != pack.TAG_COUNT || decoded.Pcode != p.Pcode || decoded.Oid != p.Oid || decoded.Time != p.Time || decoded.Onode != 0 || decoded.Okind != 0 {
		t.Fatal("wire identity/time mismatch")
	}
	assertPackMapping(t, decoded, w)
	if !bytes.Equal(pack.ToBytesPack(decoded), wire) {
		t.Fatal("wire serialization is not stable after decoding")
	}
}

func TestPackExcludesPrivateAndHighCardinalityFields(t *testing.T) {
	t.Setenv("WHATAP_ACCESSKEY", "synthetic-secret-access-key")
	w := packTestOptionalWindow(t)
	w.BytesTx, w.BytesRx, w.PacketsTx, w.PacketsRx = 123, 456, 7, 8
	w.Retransmissions, w.Losses, w.ObservationCount = 9, 10, 11
	w.Jitter = flow.Distribution{Count: 1, SumMicros: 99, MinMicros: 99, MaxMicros: 99}
	p, err := PackForWindow(w, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	assertPackMapping(t, p, w)
	for _, key := range []string{"cmd", "request_id", "PID", "pid", "comm", "cmdline", "startTimeTicks", "process_via", "p95", "srtt_p95_us", "bytesTx", "bytesRx", "bytes_tx", "bytes_rx", "packets_tx", "packets_rx", "jitter", "retransmissions", "losses", "observation_count", "license", "accesskey", "pcode", "oid", "onode", "category", "object_name"} {
		if p.Tags.ContainsKey(key) || p.Data.ContainsKey(key) {
			t.Fatalf("unexpected sensitive or unmeasured field %s", key)
		}
	}
	wire := pack.ToBytesPack(p)
	for _, secret := range []string{w.Process.Comm, w.Process.Cmdline, w.Process.Via, "synthetic-secret-access-key", "uploadNetworkEdge"} {
		if bytes.Contains(wire, []byte(secret)) {
			t.Fatal("wire contains private process data, access key or bridge command")
		}
	}
}

func TestPackInvalidIdentity(t *testing.T) {
	for _, identity := range []struct {
		pcode int64
		oid   int32
	}{{0, 1}, {-1, 1}, {1, 0}, {0, 0}} {
		p, err := PackForWindow(packTestWindow(t), identity.pcode, identity.oid)
		if err == nil || p != nil {
			t.Fatal("accepted invalid trusted identity")
		}
	}
}

func TestPackBridgeValidation(t *testing.T) {
	cases := map[string]func(*flow.Window){
		"schema":            func(w *flow.Window) { w.SchemaVersion = "network.window/v1" },
		"zero start":        func(w *flow.Window) { w.WindowStart = time.UnixMilli(0) },
		"negative start":    func(w *flow.Window) { w.WindowStart = time.UnixMilli(-1) },
		"end before start":  func(w *flow.Window) { w.WindowEnd = w.WindowStart.Add(-time.Second) },
		"empty interval":    func(w *flow.Window) { w.WindowEnd = w.WindowStart },
		"large interval":    func(w *flow.Window) { w.WindowEnd = w.WindowStart.Add(60001 * time.Millisecond) },
		"overflow time":     func(w *flow.Window) { w.WindowEnd = time.UnixMilli(1 << 53) },
		"empty node":        func(w *flow.Window) { w.Flow.NodeName = "" },
		"node whitespace":   func(w *flow.Window) { w.Flow.NodeName = "bad node" },
		"node length":       func(w *flow.Window) { w.Flow.NodeName = strings.Repeat("a", 254) },
		"protocol":          func(w *flow.Window) { w.Flow.Protocol = "udp" },
		"unspecified":       func(w *flow.Window) { w.Flow.Source.Address = "0.0.0.0" },
		"unspecified IPv6":  func(w *flow.Window) { w.Flow.Destination.Address = "::" },
		"multicast":         func(w *flow.Window) { w.Flow.Source.Address = "224.0.0.1" },
		"multicast IPv6":    func(w *flow.Window) { w.Flow.Destination.Address = "ff02::1" },
		"hostname":          func(w *flow.Window) { w.Flow.Source.Address = "localhost" },
		"zone":              func(w *flow.Window) { w.Flow.Source.Address = "fe80::1%en0" },
		"source port":       func(w *flow.Window) { w.Flow.Source.Port = 0 },
		"destination port":  func(w *flow.Window) { w.Flow.Destination.Port = 0 },
		"count limit":       func(w *flow.Window) { w.RTT.Count = 1000000001 },
		"sum overflow":      func(w *flow.Window) { w.RTT.SumMicros = 1 << 63 },
		"zero sum":          func(w *flow.Window) { w.RTT.SumMicros = 0 },
		"inconsistent sum":  func(w *flow.Window) { w.RTT.SumMicros = 31 },
		"single extrema":    func(w *flow.Window) { w.RTT.Count = 1 },
		"zero minimum":      func(w *flow.Window) { w.RTT.MinMicros = 0 },
		"reversed extrema":  func(w *flow.Window) { w.RTT.MaxMicros = 9 },
		"maximum overflow":  func(w *flow.Window) { w.RTT.MaxMicros = 1 << 53 },
		"container":         func(w *flow.Window) { w.Process.ContainerID = "bad id" },
		"container length":  func(w *flow.Window) { w.Process.ContainerID = strings.Repeat("a", 129) },
		"resolved address":  func(w *flow.Window) { w.SourceResolved.Address = "localhost" },
		"resolved port":     func(w *flow.Window) { w.DestinationResolved.Port = 0 },
		"resolution source": func(w *flow.Window) { w.SourceResolved.Via = "bad via" },
		"resolution empty":  func(w *flow.Window) { w.DestinationResolved.Via = "" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			w := packTestOptionalWindow(t)
			w.RTT = flow.Distribution{Count: 2, SumMicros: 30, MinMicros: 10, MaxMicros: 20}
			change(&w)
			_, wantErr := bridge.RequestForWindow(w)
			if wantErr == nil {
				t.Fatal("test window must fail bridge validation")
			}
			p, err := PackForWindow(w, 1, 1)
			if err == nil || p != nil || err.Error() != wantErr.Error() {
				t.Fatal("did not preserve bridge validation", err)
			}
		})
	}
}

func TestPackWindowSentinels(t *testing.T) {
	if ErrPartialWindow != bridge.ErrPartialWindow || ErrNoSamples != bridge.ErrNoSamples {
		t.Fatal("sentinels are not bridge aliases")
	}
	cases := []struct {
		name    string
		partial bool
		count   uint64
		want    error
	}{
		{name: "partial", partial: true, count: 1, want: bridge.ErrPartialWindow},
		{name: "unmeasured", count: 0, want: bridge.ErrNoSamples},
		{name: "partial and unmeasured", partial: true, count: 0, want: bridge.ErrPartialWindow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := packTestWindow(t)
			w.Partial, w.RTT.Count = tc.partial, tc.count
			p, err := PackForWindow(w, 1, 1)
			if p != nil || err != tc.want || !errors.Is(err, tc.want) {
				t.Fatal("window sentinel identity was not preserved", err)
			}
		})
	}
}

func TestPackInputImmutabilityAndIndependentMaps(t *testing.T) {
	w := packTestOptionalWindow(t)
	before, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	source, destination, process := w.SourceResolved, w.DestinationResolved, w.Process
	first, err := PackForWindow(w, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PackForWindow(w, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || first.Tags == second.Tags || first.Data == second.Data || first.Tags == first.Data {
		t.Fatal("calls share pack or map pointers")
	}
	for _, maps := range [][2]*value.MapValue{{first.Tags, second.Tags}, {first.Data, second.Data}} {
		keys := maps[0].Keys()
		for keys.HasMoreElements() {
			key := keys.NextString()
			if maps[0].Get(key) == maps[1].Get(key) {
				t.Fatalf("calls share value pointer for %s", key)
			}
		}
	}
	first.Tags.Get("observer_container_id").(*value.TextValue).Val = "mutated-pack-container"
	first.Data.Get("src_resolved_port").(*value.DecimalValue).Val = 1
	first.Category, first.Pcode, first.Onode = "mutated-category", 2, 3
	assertPackMapping(t, second, w)
	after, err := json.Marshal(w)
	if err != nil || !bytes.Equal(before, after) || w.SourceResolved != source || w.DestinationResolved != destination || w.Process != process {
		t.Fatal("conversion or pack mutation changed the input window", err)
	}
	w.Process.ContainerID = "mutated-input-container"
	w.SourceResolved.Address, w.SourceResolved.Port = "10.9.0.1", 9999
	w.DestinationResolved.Via = "mutated-input-via"
	if second.Tags.GetString("observer_container_id") != "observer-container" || second.Tags.GetString("src_resolved_addr") != "10.1.0.1" || second.Data.GetLong("src_resolved_port") != 2345 || second.Tags.GetString("dst_resolution_via") != "conntrack" {
		t.Fatal("input mutation changed a previously returned pack")
	}
	third, err := PackForWindow(w, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	assertPackMapping(t, third, w)
}
