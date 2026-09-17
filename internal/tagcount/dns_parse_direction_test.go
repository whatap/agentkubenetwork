package tagcount

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/dns"
	"github.com/whatap/agentkubenetwork/internal/flow"
)

func malformedDNSFragment() dns.Fragment {
	return dns.Fragment{
		ObservedAt: time.Unix(1720000000, 0).UTC(), NodeName: "node-a", ObserverPID: 42,
		Source:              flow.Endpoint{Address: "10.96.0.10", Port: 53},
		Destination:         flow.Endpoint{Address: "10.0.0.1", Port: 42000},
		SourceResolved:      &flow.ResolvedEndpoint{Address: "10.2.0.10", Port: 5353, Via: "conntrack"},
		DestinationResolved: &flow.ResolvedEndpoint{Address: "10.1.0.1", Port: 42001, Via: "conntrack"},
		SourcePod:           &flow.Pod{UID: "server", Namespace: "system", Name: "dns"},
		DestinationPod:      &flow.Pod{UID: "client", Namespace: "app", Name: "caller"},
		ObserverPod:         &flow.Pod{UID: "observer", Namespace: "capture", Name: "observer"},
		Payload:             []byte{0, 1, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0},
	}
}

func checkMalformedDNSOutput(t *testing.T, tx, want dns.Transaction) {
	t.Helper()
	var line bytes.Buffer
	if err := json.NewEncoder(&line).Encode(tx); err != nil {
		t.Fatal(err)
	}
	var got dns.Transaction
	if err := json.Unmarshal(line.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("JSONL direction/identity: got %+v want %+v; JSON=%s", got, want, line.String())
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(line.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"latencyMicros", "responseCode"} {
		if _, ok := fields[key]; ok {
			t.Errorf("invented JSON field %s", key)
		}
	}
	p, err := PackForDNS(got, 3895, 71)
	if err != nil {
		t.Fatal(err)
	}
	p = eventRoundTrip(t, p)
	for key, expected := range map[string]string{"client_addr": want.Client.Address, "server_addr": want.Server.Address, "observer_pod_uid": "observer", "outcome": dns.OutcomeParseError} {
		if actual := p.Tags.GetString(key); actual != expected {
			t.Errorf("TagCount %s=%q want %q", key, actual, expected)
		}
	}
	for key, expected := range map[string]int64{"client_port": int64(want.Client.Port), "server_port": int64(want.Server.Port), "observer_pid": 42, "response_count": 0} {
		if actual := p.Data.GetLong(key); actual != expected {
			t.Errorf("TagCount %s=%d want %d", key, actual, expected)
		}
	}
	for prefix, pod := range map[string]*flow.Pod{"client": want.ClientPod, "server": want.ServerPod} {
		for suffix, expected := range map[string]string{"uid": "", "namespace": "", "name": ""} {
			if pod != nil {
				switch suffix {
				case "uid":
					expected = pod.UID
				case "namespace":
					expected = pod.Namespace
				case "name":
					expected = pod.Name
				}
			}
			key := prefix + "_pod_" + suffix
			if pod == nil && p.Tags.ContainsKey(key) || p.Tags.GetString(key) != expected {
				t.Errorf("TagCount %s=%q want %q", key, p.Tags.GetString(key), expected)
			}
		}
	}
	for prefix, resolved := range map[string]*flow.ResolvedEndpoint{"client": want.ClientResolved, "server": want.ServerResolved} {
		if resolved == nil {
			if p.Tags.ContainsKey(prefix+"_resolved_addr") || p.Tags.ContainsKey(prefix+"_resolution_via") || p.Data.ContainsKey(prefix+"_resolved_port") {
				t.Errorf("invented %s resolved attribution", prefix)
			}
			for _, suffix := range []string{"Pod", "Resolved"} {
				if _, ok := fields[prefix+suffix]; ok {
					t.Errorf("invented JSON %s%s", prefix, suffix)
				}
			}
		} else if p.Tags.GetString(prefix+"_resolved_addr") != resolved.Address || p.Tags.GetString(prefix+"_resolution_via") != resolved.Via || p.Data.GetLong(prefix+"_resolved_port") != int64(resolved.Port) {
			t.Errorf("wrong %s resolved endpoint: %v %v", prefix, p.Tags, p.Data)
		}
	}
	if p.Data.ContainsKey("latency_us") || p.Tags.ContainsKey("rcode") {
		t.Error("invented latency/status")
	}
}

func TestDNSMalformedUnknownDirectionJSONLTagCount(t *testing.T) {
	for _, size := range []int{0, 1, 2, 3, 4, 11} {
		f := malformedDNSFragment()
		f.Payload = f.Payload[:size]
		want := dns.Transaction{SchemaVersion: dns.SchemaVersion, ObservedAt: f.ObservedAt, NodeName: f.NodeName, ObserverPID: f.ObserverPID,
			Protocol: "udp", Outcome: dns.OutcomeParseError, Client: f.Source, Server: f.Destination, ObserverPod: f.ObserverPod}
		txs := dns.NewCorrelator(time.Second).Process(f)
		if len(txs) != 1 {
			t.Fatalf("payload size=%d transactions=%d", size, len(txs))
		}
		checkMalformedDNSOutput(t, txs[0], want)
	}
}

func TestDNSMalformedRequestDirectionJSONLTagCount(t *testing.T) {
	f := malformedDNSFragment()
	f.Payload[2] = 0
	f.Source, f.Destination = f.Destination, f.Source
	f.SourceResolved, f.DestinationResolved = f.DestinationResolved, f.SourceResolved
	f.SourcePod, f.DestinationPod = f.DestinationPod, f.SourcePod
	want := dns.Transaction{SchemaVersion: dns.SchemaVersion, ObservedAt: f.ObservedAt, NodeName: f.NodeName, ObserverPID: f.ObserverPID,
		Protocol: "udp", Outcome: dns.OutcomeParseError, Client: f.Source, Server: f.Destination,
		ClientResolved: f.SourceResolved, ServerResolved: f.DestinationResolved, ClientPod: f.SourcePod, ServerPod: f.DestinationPod, ObserverPod: f.ObserverPod}
	txs := dns.NewCorrelator(time.Second).Process(f)
	if len(txs) != 1 {
		t.Fatalf("transactions=%d", len(txs))
	}
	checkMalformedDNSOutput(t, txs[0], want)
}

func TestDNSMalformedResponseDirectionJSONLTagCount(t *testing.T) {
	f := malformedDNSFragment()
	want := dns.Transaction{SchemaVersion: dns.SchemaVersion, ObservedAt: f.ObservedAt, NodeName: f.NodeName, ObserverPID: f.ObserverPID,
		Protocol: "udp", Outcome: dns.OutcomeParseError, Client: f.Destination, Server: f.Source,
		ClientResolved: f.DestinationResolved, ServerResolved: f.SourceResolved, ClientPod: f.DestinationPod, ServerPod: f.SourcePod, ObserverPod: f.ObserverPod}
	txs := dns.NewCorrelator(time.Second).Process(f)
	if len(txs) != 1 {
		t.Fatalf("transactions=%d", len(txs))
	}
	checkMalformedDNSOutput(t, txs[0], want)
	before, err := json.Marshal(txs[0])
	if err != nil {
		t.Fatal(err)
	}
	f.SourcePod.UID, f.DestinationPod.UID, f.ObserverPod.UID = "mutated", "mutated", "mutated"
	f.SourceResolved.Address, f.DestinationResolved.Address = "10.9.9.9", "10.9.9.8"
	after, err := json.Marshal(txs[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("transaction aliases mutable capture identity")
	}
}
