package dns

import (
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
)

func TestDNSFinalizationKeepsCapturePodIdentity(t *testing.T) {
	for _, mode := range []string{"response", "expire", "finish", "flush", "capacity", "parse", "orphan"} {
		t.Run(mode, func(t *testing.T) {
			c := NewCorrelatorWithConfig(Config{Timeout: time.Second, MaxPending: 1})
			query := safetyQuery(1, safetyBase)
			query.SourcePod = &flow.Pod{UID: "client", Namespace: "a", Name: "client"}
			query.DestinationPod = &flow.Pod{UID: "server", Namespace: "b", Name: "server"}
			query.ObserverPod = &flow.Pod{UID: "observer", Namespace: "c", Name: "observer"}
			response := safetyResponse(query, safetyBase.Add(time.Millisecond), 2_000_000)
			response.SourcePod, response.DestinationPod, response.ObserverPod = query.DestinationPod, query.SourcePod, query.ObserverPod
			if mode == "capacity" {
				c.Process(safetyQuery(2, safetyBase))
			}
			if mode == "parse" {
				// Unknown-direction payloads are covered by the fail-closed wire tests.
				query.Payload = []byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
			}
			var got []Transaction
			if mode == "orphan" {
				got = c.Process(response)
			} else {
				got = c.Process(query)
			}
			query.SourcePod.UID, query.DestinationPod.UID, query.ObserverPod.UID = "changed", "changed", "changed"
			switch mode {
			case "response":
				got = c.Process(response)
			case "expire":
				got = c.Expire(safetyBase.Add(time.Second))
			case "finish":
				got = c.Finish(safetyBase)
			case "flush":
				got = c.Flush()
			}
			if len(got) != 1 {
				t.Fatalf("expected one outcome: %+v", got)
			}
			for want, pod := range map[string]*flow.Pod{"client": got[0].ClientPod, "server": got[0].ServerPod, "observer": got[0].ObserverPod} {
				if pod == nil || pod.UID != want {
					t.Errorf("%s identity lost or mutated: %+v", want, pod)
				}
			}
		})
	}
}

func TestDNSDoesNotBackfillUnknownQueryPodFromResponse(t *testing.T) {
	c := NewCorrelator(time.Second)
	query := safetyQuery(1, safetyBase)
	c.Process(query)
	response := safetyResponse(query, safetyBase.Add(time.Millisecond), 2_000_000)
	response.SourcePod = &flow.Pod{UID: "later-server"}
	response.DestinationPod = &flow.Pod{UID: "later-client"}
	response.ObserverPod = &flow.Pod{UID: "later-observer"}
	got := c.Process(response)
	if len(got) != 1 || got[0].ClientPod != nil || got[0].ServerPod != nil || got[0].ObserverPod != nil {
		t.Fatalf("unknown query identity backfilled: %+v", got)
	}
}
