package topology

import (
	"errors"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/dns"
	"github.com/whatap/agentkubenetwork/internal/flow"
	"github.com/whatap/agentkubenetwork/internal/l7"
)

func testHTTP(at time.Time, status uint16) l7.Transaction {
	w := testWindow(at)
	w.Flow.Direction = "client-to-server"
	return l7.Transaction{SchemaVersion: l7.SchemaVersion, ObservedAt: at, Flow: w.Flow,
		Protocol: l7.ProtocolHTTP1, Source: l7.SourceKernelPlaintext, Method: "GET", StatusCode: status,
		LatencyBoundary: l7.BoundaryResponseStatus}
}

func TestHTTPMergesMonotoneFlagsAcrossPortsAndObservers(t *testing.T) {
	a, _ := New(Config{ClusterID: "cluster-a", WindowSize: time.Minute, MaxEntries: 1})
	good := testHTTP(testStart.Add(3*time.Second), 200)
	bad := testHTTP(testStart.Add(time.Second), 503)
	bad.Flow.NodeName, bad.Flow.Source.Port = "another-node", 51234
	for _, tx := range []l7.Transaction{good, bad, good} {
		if err := a.ObserveL7(tx); err != nil {
			t.Fatal(err)
		}
	}
	rows := a.FlushAll()
	if len(rows) != 1 || !rows[0].Observed || !rows[0].ResultObserved || !rows[0].ErrorObserved || rows[0].LastSeenMS != good.ObservedAt.UnixMilli() || rows[0].Direction != DirectionRequest || rows[0].DestinationPort != good.Flow.Destination.Port {
		t.Fatalf("wrong HTTP summary: %+v", rows)
	}
	if err := ValidateSummary(rows[0]); err != nil {
		t.Fatal(err)
	}
	// A late older result after drain is a MAX-safe correction, never dropped.
	if err := a.ObserveL7(bad); err != nil || len(a.FlushAll()) != 1 {
		t.Fatalf("late correction: %v", err)
	}
	bad.LatencyBoundary = l7.BoundaryResponseHeaders
	if err := a.ObserveL7(bad); !errors.Is(err, ErrInvalidObservation) {
		t.Fatal("invalid measurement boundary admitted")
	}
}

func TestDNSResultAndUnknownOutcomeRemainDistinct(t *testing.T) {
	for _, tc := range []struct {
		name, outcome, rcode string
		measured             bool
		latency              uint64
		known, failure       bool
	}{
		{"success", dns.OutcomeResponse, "NOERROR", true, 10, true, false},
		{"nxdomain answer is not a failure", dns.OutcomeResponse, "NXDOMAIN", true, 10, true, false},
		{"servfail", dns.OutcomeResponse, "SERVFAIL", true, 10, true, true},
		{"refused", dns.OutcomeResponse, "REFUSED", true, 10, true, true},
		{"measured zero sample is a result", dns.OutcomeResponse, "NOERROR", true, 0, true, false},
		{"measured zero servfail is an error", dns.OutcomeResponse, "SERVFAIL", true, 0, true, true},
		{"orphan response", dns.OutcomeResponse, "NOERROR", false, 0, false, false},
		{"orphan servfail is not a confirmed error", dns.OutcomeResponse, "SERVFAIL", false, 0, false, false},
		{"timeout", dns.OutcomeNoResponse, "", false, 0, false, false},
		{"parse", dns.OutcomeParseError, "", false, 0, false, false},
		{"incomplete", dns.OutcomeIncomplete, "", false, 0, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := New(Config{ClusterID: "cluster-a", WindowSize: time.Minute, MaxEntries: 1})
			tx := dns.Transaction{SchemaVersion: dns.SchemaVersion, ObservedAt: testStart.Add(time.Second), NodeName: "node", Protocol: "udp",
				Client: flow.Endpoint{Address: "10.0.0.1", Port: 42000}, Server: flow.Endpoint{Address: "10.0.0.53", Port: 53},
				Outcome: tc.outcome, ResponseCode: tc.rcode, LatencyMeasured: tc.measured, LatencyMicros: tc.latency}
			if err := a.ObserveDNS(tx); err != nil {
				t.Fatal(err)
			}
			rows := a.FlushAll()
			if len(rows) != 1 || rows[0].ResultObserved != tc.known || rows[0].ErrorObserved != tc.failure {
				t.Fatalf("wrong DNS result: %+v", rows)
			}
			if err := ValidateSummary(rows[0]); err != nil {
				t.Fatal(err)
			}
			if tc.outcome == dns.OutcomeParseError && (rows[0].Direction != DirectionUnknown || rows[0].DestinationPort != 0) {
				t.Fatal("unparseable DNS invented request direction")
			}
			tx.Client = flow.Endpoint{Address: "0.0.0.0"}
			if err := a.ObserveDNS(tx); err != nil || a.Len() != 0 {
				t.Fatalf("unattributable DNS must remain raw-only: %v", err)
			}
		})
	}
}

// The correlator reports a latency only when it measured one, and it measures
// only responses. Like the DNS pack, the summary rejects any other record.
func TestDNSRejectsLatencyThatWasNotMeasured(t *testing.T) {
	for name, mutate := range map[string]func(*dns.Transaction){
		"latency without measurement": func(tx *dns.Transaction) { tx.LatencyMeasured = false },
		"measurement without a response": func(tx *dns.Transaction) {
			tx.Outcome, tx.ResponseCode, tx.LatencyMicros = dns.OutcomeNoResponse, "", 0
		},
	} {
		t.Run(name, func(t *testing.T) {
			a, _ := New(Config{ClusterID: "cluster-a", WindowSize: time.Minute, MaxEntries: 1})
			tx := dns.Transaction{SchemaVersion: dns.SchemaVersion, ObservedAt: testStart.Add(time.Second), NodeName: "node", Protocol: "udp",
				Client: flow.Endpoint{Address: "10.0.0.1", Port: 42000}, Server: flow.Endpoint{Address: "10.0.0.53", Port: 53},
				Outcome: dns.OutcomeResponse, ResponseCode: "NOERROR", LatencyMeasured: true, LatencyMicros: 10}
			if err := a.ObserveDNS(tx); err != nil || len(a.FlushAll()) != 1 {
				t.Fatalf("the unmodified record must be valid: %v", err)
			}
			mutate(&tx)
			if err := a.ObserveDNS(tx); !errors.Is(err, ErrInvalidObservation) || a.Len() != 0 {
				t.Fatalf("an impossible latency state was admitted: err=%v entries=%d", err, a.Len())
			}
		})
	}
}

func TestSummaryValidationRejectsContradictions(t *testing.T) {
	a, _ := New(Config{ClusterID: "cluster-a", WindowSize: time.Minute, MaxEntries: 1})
	if err := a.ObserveWindow(testWindow(testStart.Add(time.Second))); err != nil {
		t.Fatal(err)
	}
	valid := a.FlushAll()[0]
	for _, mutate := range []func(*Summary){
		func(s *Summary) { s.ClusterID = "" },
		func(s *Summary) { s.Observed = false },
		func(s *Summary) { s.LastSeenMS = s.WindowEnd.UnixMilli() },
		func(s *Summary) { s.ErrorObserved = true },
		func(s *Summary) { s.ResultObserved = true },
		func(s *Summary) { s.Direction = DirectionRequest },
		func(s *Summary) { s.DestinationPort = 40000 },
		func(s *Summary) { s.Source.UID = "fake-address-uid" },
		func(s *Summary) { s.WindowEnd = s.WindowStart.Add(2 * time.Minute) },
	} {
		bad := valid
		mutate(&bad)
		if err := ValidateSummary(bad); err == nil {
			t.Fatalf("invalid summary admitted: %+v", bad)
		}
	}
}
