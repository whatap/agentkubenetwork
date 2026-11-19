package topology

import (
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/dns"
	"github.com/whatap/agentkubenetwork/internal/flow"
)

func testDNS(at time.Time, rcode string) dns.Transaction {
	return dns.Transaction{SchemaVersion: dns.SchemaVersion, ObservedAt: at, NodeName: "node", Protocol: "udp",
		Client: flow.Endpoint{Address: "10.0.0.1", Port: 42000}, Server: flow.Endpoint{Address: "10.0.0.53", Port: 53},
		Outcome: dns.OutcomeResponse, ResponseCode: rcode, LatencyMeasured: true, LatencyMicros: 10}
}

// Status 400 is the first HTTP error. A redirect or 399 is a result without one.
func TestHTTPErrorStartsAtStatus400(t *testing.T) {
	for status, failure := range map[uint16]bool{200: false, 302: false, 399: false, 400: true, 404: true, 499: true, 500: true, 599: true} {
		a, _ := New(Config{ClusterID: "cluster-a", WindowSize: time.Minute, MaxEntries: 1})
		if err := a.ObserveL7(testHTTP(testStart.Add(time.Second), status)); err != nil {
			t.Fatalf("status %d: %v", status, err)
		}
		rows := a.FlushAll()
		if len(rows) != 1 || !rows[0].ResultObserved || rows[0].ErrorObserved != failure {
			t.Fatalf("status %d: %+v; want a result with error=%v", status, rows, failure)
		}
	}
}

// Evidence for one relationship only grows inside a window. A later record
// without an error or without a result must not clear what an earlier one showed.
func TestEvidenceFlagsAreMergedNotOverwritten(t *testing.T) {
	a, _ := New(Config{ClusterID: "cluster-a", WindowSize: time.Minute, MaxEntries: 1})
	failed := testDNS(testStart.Add(time.Second), "SERVFAIL")
	answered := testDNS(testStart.Add(2*time.Second), "NOERROR")
	unanswered := testDNS(testStart.Add(3*time.Second), "")
	unanswered.Outcome, unanswered.LatencyMeasured, unanswered.LatencyMicros = dns.OutcomeNoResponse, false, 0
	for _, tx := range []dns.Transaction{failed, answered, unanswered} {
		if err := a.ObserveDNS(tx); err != nil {
			t.Fatal(err)
		}
	}
	rows := a.FlushAll()
	if len(rows) != 1 || !rows[0].Observed || !rows[0].ResultObserved || !rows[0].ErrorObserved {
		t.Fatalf("a later record cleared earlier evidence: %+v", rows)
	}
	if err := ValidateSummary(rows[0]); err != nil {
		t.Fatal(err)
	}
}

// last_seen_ms is the latest observation, also when an older one arrives later.
func TestLastSeenIsTheLatestObservationInAnyArrivalOrder(t *testing.T) {
	a, _ := New(Config{ClusterID: "cluster-a", WindowSize: time.Minute, MaxEntries: 1})
	newer, older := testWindow(testStart.Add(30*time.Second)), testWindow(testStart.Add(10*time.Second))
	for _, w := range []flow.Window{newer, older} {
		if err := a.ObserveWindow(w); err != nil {
			t.Fatal(err)
		}
	}
	rows := a.FlushAll()
	if len(rows) != 1 || rows[0].LastSeenMS != newer.LastObservedAt.UnixMilli() {
		t.Fatalf("an older observation moved last seen back: %+v", rows)
	}
}

// An error is only meaningful together with a result. The rule must hold for a
// request relationship too, where each flag on its own is allowed.
func TestSummaryValidationRejectsAnErrorWithoutAResult(t *testing.T) {
	a, _ := New(Config{ClusterID: "cluster-a", WindowSize: time.Minute, MaxEntries: 1})
	if err := a.ObserveL7(testHTTP(testStart.Add(time.Second), 503)); err != nil {
		t.Fatal(err)
	}
	valid := a.FlushAll()[0]
	if err := ValidateSummary(valid); err != nil {
		t.Fatal(err)
	}
	bad := valid
	bad.ResultObserved = false
	if err := ValidateSummary(bad); err == nil {
		t.Fatalf("an error without a result was admitted: %+v", bad)
	}
}

// When the collector resolved the NAT destination, the request port and the
// unresolved peer address are the resolved ones, not those of the service.
func TestRequestDestinationIsTheResolvedEndpoint(t *testing.T) {
	a, _ := New(Config{ClusterID: "cluster-a", WindowSize: time.Minute, MaxEntries: 2})
	request := testHTTP(testStart.Add(time.Second), 200)
	request.DestinationResolved = &flow.ResolvedEndpoint{Address: "10.0.9.9", Port: 8443, Via: "conntrack"}
	query := testDNS(testStart.Add(time.Second), "NOERROR")
	query.ServerResolved = &flow.ResolvedEndpoint{Address: "10.0.9.53", Port: 5353, Via: "conntrack"}
	if err := a.ObserveL7(request); err != nil {
		t.Fatal(err)
	}
	if err := a.ObserveDNS(query); err != nil {
		t.Fatal(err)
	}
	got := map[string]Summary{}
	for _, row := range a.FlushAll() {
		got[row.Protocol] = row
	}
	if row := got["http1"]; row.Destination.Address != "10.0.9.9" || row.DestinationPort != 8443 {
		t.Fatalf("HTTP destination is not the resolved endpoint: %+v", row)
	}
	if row := got["dns"]; row.Destination.Address != "10.0.9.53" || row.DestinationPort != 5353 {
		t.Fatalf("DNS destination is not the resolved endpoint: %+v", row)
	}
}
