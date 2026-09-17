package l7

import (
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
	"golang.org/x/net/http2/hpack"
)

func TestHTTP2KeepsFirstRequestPodIdentity(t *testing.T) {
	for _, known := range []bool{true, false} {
		t.Run(map[bool]string{true: "known", false: "unknown"}[known], func(t *testing.T) {
			c := NewCorrelator(Config{})
			client, server := flow.Endpoint{Address: "10.0.0.1", Port: 41000}, flow.Endpoint{Address: "10.0.0.2", Port: 8080}
			request := Fragment{ObservedAt: time.Unix(100, 0), KernelTimestampNS: 1_000_000, NodeName: "node", ObserverPID: 42, Source: SourceOpenSSL, SourceEndpoint: client, DestinationEndpoint: server}
			if known {
				request.SourcePod = &flow.Pod{UID: "client-before", Namespace: "a", Name: "client"}
				request.DestinationPod = &flow.Pod{UID: "server-before", Namespace: "b", Name: "server"}
				request.ObserverPod = &flow.Pod{UID: "observer-before", Namespace: "c", Name: "observer"}
			}
			request.Payload = append([]byte(http2ClientPreface), http2TestHeadersFrame(t, newHPACKTestEncoder(t), 1, hpack.HeaderField{Name: ":method", Value: "GET"}, hpack.HeaderField{Name: ":path", Value: "/"})...)
			if out := c.Process(request); len(out) != 0 {
				t.Fatal(out)
			}
			if known {
				request.SourcePod.UID, request.DestinationPod.UID, request.ObserverPod.UID = "changed", "changed", "changed"
			}
			response := request
			response.KernelTimestampNS = 3_000_000
			response.SourceEndpoint, response.DestinationEndpoint = server, client
			response.SourcePod, response.DestinationPod, response.ObserverPod = &flow.Pod{UID: "response-source"}, &flow.Pod{UID: "response-destination"}, &flow.Pod{UID: "response-observer"}
			response.Payload = http2TestHeadersFrame(t, newHPACKTestEncoder(t), 1, hpack.HeaderField{Name: ":status", Value: "200"})
			out := c.Process(response)
			if len(out) != 1 || out[0].Transaction == nil {
				t.Fatalf("no transaction: %+v", out)
			}
			tx := out[0].Transaction
			for label, pod := range map[string]*flow.Pod{"client-before": tx.SourcePod, "server-before": tx.DestinationPod, "observer-before": tx.ObserverPod} {
				if known && (pod == nil || pod.UID != label) || !known && pod != nil {
					t.Errorf("request-time %s identity replaced: %+v", label, pod)
				}
			}
		})
	}
}
