package tagcount

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/dns"
)

func TestDNSLatencyRequiresMeasuredCorrelation(t *testing.T) {
	for _, tc := range []struct {
		name                string
		matched             bool
		queryNS, responseNS uint64
		measured            bool
		micros              int64
	}{
		{"unmatched", false, 1000, 2000, false, 0},
		{"missing_query_timestamp", true, 0, 2000, false, 0},
		{"missing_response_timestamp", true, 1000, 0, false, 0},
		{"both_missing", true, 0, 0, false, 0},
		{"inverted", true, 2000, 1000, false, 0},
		{"submicrosecond", true, 1000, 1500, true, 0},
		{"equal_nonzero", true, 1000, 1000, true, 0},
		{"ordinary", true, 1000, 9000, true, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := malformedDNSFragment()
			q.Source, q.Destination = q.Destination, q.Source
			q.SourceResolved, q.DestinationResolved = nil, nil
			q.SourcePod, q.DestinationPod = nil, nil
			q.Payload = []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}
			q.KernelTimestampNS = tc.queryNS
			r := q
			r.Source, r.Destination = q.Destination, q.Source
			r.KernelTimestampNS = tc.responseNS
			r.ObservedAt = q.ObservedAt.Add(time.Millisecond)
			r.Payload = append([]byte(nil), q.Payload...)
			r.Payload[2] = 0x81
			r.Payload[3] = 0x83
			c := dns.NewCorrelator(time.Second)
			if tc.matched {
				c.Process(q)
			}
			txs := c.Process(r)
			if len(txs) != 1 {
				t.Fatalf("transactions=%d", len(txs))
			}
			tx := txs[0]
			p, err := PackForDNS(tx, 1, 1)
			if err != nil {
				t.Fatal(err)
			}
			p = eventRoundTrip(t, p)
			if p.Data.ContainsKey("latency_us") != tc.measured {
				t.Errorf("unmeasured latency must not become zero sample: measured=%t data=%v", tc.measured, p.Data)
			}
			if tc.measured && p.Data.GetLong("latency_us") != tc.micros {
				t.Errorf("latency=%d", p.Data.GetLong("latency_us"))
			}
			if p.Data.GetLong("response_count") != 1 || p.Tags.GetString("rcode") != "NXDOMAIN" || p.Tags.GetString("query_name") != "test" || tx.Outcome != dns.OutcomeResponse {
				t.Fatal("response metadata lost")
			}
			data, err := json.Marshal(tx)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			measured, _ := fields["latencyMeasured"].(bool)
			if measured != tc.measured {
				t.Errorf("measurement validity lost in JSON: %s", data)
			}
			if !tc.measured {
				if _, ok := fields["latencyMicros"]; ok {
					t.Errorf("invented JSON latency: %s", data)
				}
			}
		})
	}
}

func TestDNSRejectsContradictoryMeasurementValidity(t *testing.T) {
	for _, tc := range []struct {
		name     string
		measured bool
		outcome  string
		micros   uint64
	}{
		{"value_without_measurement", false, dns.OutcomeResponse, 1},
		{"measurement_without_response", true, dns.OutcomeNoResponse, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := eventDNS()
			tx.Outcome = tc.outcome
			tx.ResponseCode = ""
			tx.LatencyMicros = tc.micros
			raw, _ := json.Marshal(tx)
			var fields map[string]any
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			fields["latencyMeasured"] = tc.measured
			raw, _ = json.Marshal(fields)
			if err := json.Unmarshal(raw, &tx); err != nil {
				t.Fatal(err)
			}
			if p, err := PackForDNS(tx, 1, 1); err == nil || p != nil {
				t.Fatal("contradictory measurement accepted")
			}
		})
	}
}
