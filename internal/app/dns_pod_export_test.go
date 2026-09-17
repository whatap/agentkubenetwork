package app

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/collector"
	"github.com/whatap/agentkubenetwork/internal/flow"
	"github.com/whatap/agentkubenetwork/internal/tagcount"
	"github.com/whatap/golib/lang/pack"
)

func TestDNSPodUIDSurvivesQueryCaptureThroughTagCount(t *testing.T) {
	query := dnsQueryEvent()
	query.TimestampNS = 1_000_000
	response := query
	response.TimestampNS = 2_000_000
	response.SourcePort, response.DestinationPort = query.DestinationPort, query.SourcePort
	response.SourceAddress, response.DestinationAddress = query.DestinationAddress, query.SourceAddress
	response.Payload = append([]byte(nil), query.Payload...)
	response.Payload[2] = 0x81
	client := &flow.Pod{UID: "client-at-query", Namespace: "client-ns", Name: "client"}
	server := &flow.Pod{UID: "server-at-query", Namespace: "server-ns", Name: "server"}
	observer := &flow.Pod{UID: "observer-at-query", Namespace: "observer-ns", Name: "observer"}
	calls := 0
	pods := podEnricherFunc(func(o *flow.Observation) {
		calls++
		if o.Process == nil || o.DestinationResolved == nil {
			t.Fatal("Pod lookup preceded process/NAT lookup")
		}
		if calls > 1 {
			client.UID, server.UID, observer.UID = "later-client", "later-server", "later-observer"
		}
		o.SourcePod, o.DestinationPod, o.ObserverPod = client, server, observer
	})
	exporter := &recordingTypedExporter{recordingWindowExporter: recordingWindowExporter{failed: make(chan struct{})}}
	var output bytes.Buffer
	err := RunEventsWithOptions(context.Background(), &fakeEventReader{events: []collector.Event{query, response}}, &output, "node", 0,
		func() time.Time { return time.Unix(100, 0) }, &requestIdentityResolver{}, &requestProcessResolver{},
		EventOptions{OutputMode: "windows", PodEnricher: pods, WindowExporter: exporter})
	if err != nil {
		t.Fatal(err)
	}
	if len(exporter.dns) != 1 {
		t.Fatalf("expected one DNS observation: %+v", exporter.dns)
	}
	p, err := tagcount.PackForDNS(exporter.dns[0], 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	decoded := pack.ToPack(pack.ToBytesPack(p)).(*pack.TagCountPack)
	for prefix, want := range map[string]string{"client": "client-at-query", "server": "server-at-query", "observer": "observer-at-query"} {
		if got := decoded.Tags.GetString(prefix + "_pod_uid"); got != want {
			t.Errorf("%s Pod UID lost or replaced: got %q want %q", prefix, got, want)
		}
	}
	var raw map[string]any
	if err := json.NewDecoder(&output).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"clientPod": "client-at-query", "serverPod": "server-at-query", "observerPod": "observer-at-query"} {
		pod, ok := raw[key].(map[string]any)
		if !ok || pod["uid"] != want {
			t.Errorf("JSONL %s missing query-time UID: %+v", key, raw[key])
		}
	}
}
