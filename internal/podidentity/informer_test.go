package podidentity

import (
	"context"
	"encoding/json"
	"github.com/whatap/agentkubenetwork/internal/flow"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestInformerListWatchAndCancellation(t *testing.T) {
	var lists atomic.Int32
	watched := make(chan string, 1)
	disconnected := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/pods" {
			t.Errorf("unexpected resource %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("watch") != "true" {
			lists.Add(1)
			_ = json.NewEncoder(w).Encode(core.PodList{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "PodList"}, ListMeta: meta.ListMeta{ResourceVersion: "17"}, Items: []core.Pod{*pod("first", "10.0.0.1")}})
			return
		}
		watched <- r.URL.Query().Get("resourceVersion")
		p := pod("first", "10.0.0.2")
		p.TypeMeta = meta.TypeMeta{APIVersion: "v1", Kind: "Pod"}
		p.ResourceVersion = "18"
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "MODIFIED", "object": p})
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		disconnected <- struct{}{}
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, stop, err := Start(ctx, &rest.Config{Host: server.URL}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	select {
	case rv := <-watched:
		if rv != "17" {
			t.Fatalf("WATCH RV=%s", rv)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no WATCH")
	}
	deadline := time.Now().Add(time.Second)
	for {
		o := flow.Observation{Flow: flow.FlowKey{Source: flow.Endpoint{Address: "10.0.0.2"}}}
		c.Enrich(&o)
		if o.SourcePod != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("MODIFIED not indexed")
		}
		time.Sleep(time.Millisecond)
	}
	if lists.Load() != 1 {
		t.Fatalf("LIST count %d", lists.Load())
	}
	cancel()
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("watch not cancelled")
	}
	o := flow.Observation{Flow: flow.FlowKey{Source: flow.Endpoint{Address: "10.0.0.2"}}}
	c.Enrich(&o)
	if o.SourcePod != nil {
		t.Fatal("stopped cache attributed")
	}
}
func TestInformerSyncTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	started := time.Now()
	_, _, err := Start(context.Background(), &rest.Config{Host: server.URL}, 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected sync timeout")
	}
	if time.Since(started) > time.Second {
		t.Fatal("unbounded startup")
	}
}
