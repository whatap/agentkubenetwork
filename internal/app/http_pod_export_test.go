package app

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
	"github.com/whatap/agentkubenetwork/internal/tagcount"
	"github.com/whatap/golib/lang/pack"
)

func TestHTTPPodUIDSurvivesRequestCaptureThroughTagCount(t *testing.T) {
	at := time.Unix(100, 0)
	source := &flow.Pod{UID: "source-at-request", Namespace: "client-ns", Name: "client"}
	destination := &flow.Pod{UID: "destination-at-request", Namespace: "server-ns", Name: "server"}
	observer := &flow.Pod{UID: "observer-at-request", Namespace: "observer-ns", Name: "observer"}
	calls := 0
	pods := podEnricherFunc(func(o *flow.Observation) {
		calls++
		if o.Process == nil || o.Process.ContainerID != "container-at-request" || o.DestinationResolved == nil {
			t.Fatal("Pod lookup must follow process and NAT resolution")
		}
		if calls > 1 {
			source.UID, destination.UID, observer.UID = "later-source", "later-destination", "later-observer"
		}
		o.SourcePod, o.DestinationPod, o.ObserverPod = source, destination, observer
	})
	exporter := &recordingTypedExporter{recordingWindowExporter: recordingWindowExporter{failed: make(chan struct{})}}
	var output bytes.Buffer
	err := RunEventsWithOptions(context.Background(), &fakeEventReader{events: httpIdentityEvents()}, &output, "node", 0,
		func() time.Time { return at }, &requestIdentityResolver{}, &requestProcessResolver{},
		EventOptions{OutputMode: "windows", PodEnricher: pods, WindowExporter: exporter})
	if err != nil {
		t.Fatal(err)
	}
	if len(exporter.http) != 1 {
		t.Fatalf("expected one HTTP observation: %+v", exporter.http)
	}
	p, err := tagcount.PackForL7(exporter.http[0], 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	decoded := pack.ToPack(pack.ToBytesPack(p)).(*pack.TagCountPack)
	for prefix, want := range map[string]string{"src": "source-at-request", "dst": "destination-at-request", "observer": "observer-at-request"} {
		if got := decoded.Tags.GetString(prefix + "_pod_uid"); got != want {
			t.Errorf("%s Pod UID lost or replaced at response: got %q want %q", prefix, got, want)
		}
	}
	var raw map[string]any
	if err := json.NewDecoder(&output).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"sourcePod": "source-at-request", "destinationPod": "destination-at-request", "observerPod": "observer-at-request"} {
		pod, ok := raw[key].(map[string]any)
		if !ok || pod["uid"] != want {
			t.Errorf("JSONL %s missing capture-time UID: %+v", key, raw[key])
		}
	}
}
