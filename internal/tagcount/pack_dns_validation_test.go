package tagcount

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/dns"
	"github.com/whatap/agentkubenetwork/internal/flow"
)

func TestPackForDNSRejectsMalformedObservation(t *testing.T) {
	cases := map[string]func(*dns.Transaction){
		"schema":                func(x *dns.Transaction) { x.SchemaVersion = "unknown" },
		"protocol":              func(x *dns.Transaction) { x.Protocol = "tcp" },
		"time":                  func(x *dns.Transaction) { x.ObservedAt = time.Time{} },
		"node":                  func(x *dns.Transaction) { x.NodeName = "node\nother" },
		"client":                func(x *dns.Transaction) { x.Client.Address = "not-an-ip" },
		"server_zone":           func(x *dns.Transaction) { x.Server.Address = "fe80::1%zone" },
		"name":                  func(x *dns.Transaction) { x.QueryName = "name\nheader" },
		"long_name":             func(x *dns.Transaction) { x.QueryName = strings.Repeat("a", 254) },
		"type":                  func(x *dns.Transaction) { x.QueryType = "A\x00" },
		"rcode":                 func(x *dns.Transaction) { x.ResponseCode = "NOERROR\n" },
		"outcome":               func(x *dns.Transaction) { x.Outcome = "success" },
		"reason":                func(x *dns.Transaction) { x.Reason = "private text" },
		"overflow":              func(x *dns.Transaction) { x.LatencyMicros = math.MaxUint64 },
		"contradictory_latency": func(x *dns.Transaction) { x.Outcome = dns.OutcomeNoResponse; x.ResponseCode = "" },
		"contradictory_rcode":   func(x *dns.Transaction) { x.Outcome = dns.OutcomeNoResponse; x.LatencyMicros = 0 },
		"pid":                   func(x *dns.Transaction) { x.ObserverPID = 42; x.Process = &flow.Process{PID: 43} },
		"container":             func(x *dns.Transaction) { x.Process = &flow.Process{ContainerID: "id\nprivate"} },
		"translation": func(x *dns.Transaction) {
			x.ServerResolved = &flow.ResolvedEndpoint{Address: "bad", Port: 53, Via: "conntrack"}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			x := eventDNS()
			change(&x)
			p, err := PackForDNS(x, 3895, 71)
			if err == nil || p != nil {
				t.Fatal("malformed DNS observation was accepted")
			}
		})
	}
	for _, id := range []struct {
		pcode int64
		oid   int32
	}{{0, 1}, {-1, 1}, {1, 0}} {
		if p, err := PackForDNS(eventDNS(), id.pcode, id.oid); err == nil || p != nil {
			t.Fatal("invalid DNS pack identity was accepted")
		}
	}
}
