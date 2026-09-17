package dns

import (
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
)

func TestCorrelatorEnrichmentSnapshot(t *testing.T) {
	for _, mode := range []string{"response", "expire", "finish", "flush", "capacity", "parse", "orphan"} {
		t.Run(mode, func(t *testing.T) {
			c := NewCorrelatorWithConfig(Config{Timeout: time.Second, MaxPending: 1})
			query := safetyQuery(1, safetyBase)
			query.ObserverPID = 42
			query.Process = &flow.Process{PID: 42, StartTimeTicks: 7, Comm: "client", Cmdline: "client --dns", ContainerID: "container-a", Via: "procfs"}
			query.SourceResolved = &flow.ResolvedEndpoint{Address: "192.0.2.1", Port: 40000, Via: "conntrack"}
			query.DestinationResolved = &flow.ResolvedEndpoint{Address: "192.0.2.53", Port: 53, Via: "conntrack"}
			wantProcess, wantClient, wantServer := *query.Process, *query.SourceResolved, *query.DestinationResolved
			wantProcess.Cmdline = "" // command lines are not observation identity
			response := safetyResponse(query, safetyBase.Add(time.Millisecond), 2_000_000)
			response.SourceResolved, response.DestinationResolved = query.DestinationResolved, query.SourceResolved
			if mode == "capacity" {
				c.Process(safetyQuery(2, safetyBase))
			}
			if mode == "parse" {
				// Preserve attribution only when the malformed query has a full header.
				query.Payload = []byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
			}
			var got []Transaction
			if mode == "orphan" {
				got = c.Process(response)
			} else {
				got = c.Process(query)
			}
			for _, pending := range c.pending {
				if pending.fragment.Payload != nil {
					t.Fatal("pending state retains raw DNS payload")
				}
			}
			// Input enrichment and payload may be reused by the capture pipeline.
			query.Process.Comm, query.Process.StartTimeTicks = "changed", 99
			query.SourceResolved.Address, query.DestinationResolved.Address = "changed-client", "changed-server"
			query.Payload[0] ^= 0xff
			switch mode {
			case "response":
				response.Process = &flow.Process{PID: 42, Comm: "later-process"}
				response.SourceResolved = &flow.ResolvedEndpoint{Address: "later-server"}
				response.DestinationResolved = &flow.ResolvedEndpoint{Address: "later-client"}
				got = c.Process(response)
			case "expire":
				got = c.Expire(safetyBase.Add(time.Second))
			case "finish":
				got = c.Finish(safetyBase)
			case "flush":
				got = c.Flush()
			}
			if len(got) != 1 {
				t.Fatalf("want transaction, got %+v", got)
			}
			tx := got[0]
			if tx.ObserverPID != 42 || tx.Process == nil || *tx.Process != wantProcess || tx.ClientResolved == nil || *tx.ClientResolved != wantClient || tx.ServerResolved == nil || *tx.ServerResolved != wantServer {
				t.Fatalf("capture-time enrichment not preserved: %+v", tx)
			}
			if tx.Process == query.Process || tx.ClientResolved == query.SourceResolved || tx.ServerResolved == query.DestinationResolved {
				t.Fatal("transaction aliases caller enrichment")
			}
			if tx.Client != query.Source || tx.Server != query.Destination || tx.QueryName == "" && mode != "parse" {
				t.Fatalf("canonical tuple or parsed question changed: %+v", tx)
			}
		})
	}
}

func TestCorrelatorPreservesUnknownQueryEnrichment(t *testing.T) {
	c := NewCorrelator(time.Second)
	query := safetyQuery(1, safetyBase)
	c.Process(query)
	response := safetyResponse(query, safetyBase.Add(time.Millisecond), 2_000_000)
	response.Process = &flow.Process{PID: 99}
	response.SourceResolved = &flow.ResolvedEndpoint{Address: "later-server"}
	response.DestinationResolved = &flow.ResolvedEndpoint{Address: "later-client"}
	got := c.Process(response)
	if len(got) != 1 || got[0].Process != nil || got[0].ClientResolved != nil || got[0].ServerResolved != nil {
		t.Fatalf("unknown query identity must not be filled from a later response: %+v", got)
	}
}
