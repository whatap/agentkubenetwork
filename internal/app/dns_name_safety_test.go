package app

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/collector"
	"github.com/whatap/agentkubenetwork/internal/dns"
	"github.com/whatap/agentkubenetwork/internal/tagcount"
	"github.com/whatap/golib/lang/pack"
)

type validatingDNSExporter struct {
	recordingTypedExporter
	packs []*pack.TagCountPack
}

func (e *validatingDNSExporter) ExportDNS(tx dns.Transaction) error {
	p, err := tagcount.PackForDNS(tx, 1, 1)
	if err != nil {
		return err
	}
	e.packs = append(e.packs, p)
	return e.recordingTypedExporter.ExportDNS(tx)
}

func TestCapturedDNSNamesCannotTerminateCollector(t *testing.T) {
	for name, labels := range map[string][]string{
		"binary": {"bad\x00\xff"}, "space": {"bad name"},
		"overlong": {strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 62)},
		"maximum":  {strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 61)},
	} {
		for _, response := range []bool{false, true} {
			direction := "query"
			if response {
				direction = "response"
			}
			t.Run(name+"/"+direction, func(t *testing.T) {
				hostile := dnsQueryEvent()
				hostile.Payload = append([]byte(nil), hostile.Payload[:12]...)
				for _, label := range labels {
					hostile.Payload = append(hostile.Payload, byte(len(label)))
					hostile.Payload = append(hostile.Payload, []byte(label)...)
				}
				hostile.Payload = append(hostile.Payload, 0, 0, 1, 0, 1)
				if response {
					hostile.Payload[2] = 0x81
					hostile.SourcePort, hostile.DestinationPort = hostile.DestinationPort, hostile.SourcePort
					hostile.SourceAddress, hostile.DestinationAddress = hostile.DestinationAddress, hostile.SourceAddress
				}
				query := dnsQueryEvent()
				query.TimestampNS = 1_000_000
				reply := query
				reply.TimestampNS = 2_000_000
				reply.SourcePort, reply.DestinationPort = query.DestinationPort, query.SourcePort
				reply.SourceAddress, reply.DestinationAddress = query.DestinationAddress, query.SourceAddress
				reply.Payload = append([]byte(nil), query.Payload...)
				reply.Payload[2] = 0x81
				exporter := &validatingDNSExporter{recordingTypedExporter: recordingTypedExporter{recordingWindowExporter: recordingWindowExporter{failed: make(chan struct{})}}}
				var out bytes.Buffer
				err := RunEventsWithOptions(context.Background(), &fakeEventReader{events: []collector.Event{hostile, query, reply}}, &out, "node", 0, func() time.Time { return time.Unix(100, 0) }, nil, nil, EventOptions{OutputMode: "windows", WindowExporter: exporter})
				if err != nil {
					t.Fatalf("captured packet terminated collector: %v", err)
				}
				if len(exporter.dns) != 2 {
					t.Fatalf("lost traffic: %+v", exporter.dns)
				}
				ordinary, failures := 0, 0
				for i, tx := range exporter.dns {
					if tx.QueryName == "test" && tx.Outcome == dns.OutcomeResponse {
						ordinary++
					}
					if len(tx.QueryName) > 253 {
						t.Fatal("unbounded question")
					}
					if tx.Outcome == dns.OutcomeParseError {
						failures++
						if tx.QueryName != "" || tx.QueryType != "" || exporter.packs[i].Tags.ContainsKey("query_name") {
							t.Fatal("malformed question leaked")
						}
					}
				}
				if ordinary != 1 || (name != "maximum" && failures != 1) || (name == "maximum" && failures != 0) {
					t.Fatalf("ordinary=%d parse failures=%d", ordinary, failures)
				}
				var records []dns.Transaction
				dec := json.NewDecoder(&out)
				for dec.More() {
					var tx dns.Transaction
					if err := dec.Decode(&tx); err != nil {
						t.Fatal(err)
					}
					records = append(records, tx)
				}
				if len(records) != 2 {
					t.Fatalf("JSONL records=%d", len(records))
				}
				if name != "maximum" {
					for _, tx := range records {
						if tx.QueryName != "" && tx.QueryName != "test" {
							t.Fatal("raw malformed label leaked to JSONL")
						}
					}
				}
			})
		}
	}
}
