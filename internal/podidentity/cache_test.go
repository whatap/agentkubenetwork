package podidentity

import (
	"github.com/whatap/agentkubenetwork/internal/flow"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"testing"
	"time"
)

func pod(uid, ip string) *core.Pod {
	return &core.Pod{ObjectMeta: meta.ObjectMeta{Name: uid, Namespace: "ns", UID: types.UID(uid)}, Status: core.PodStatus{PodIP: ip}}
}
func TestHostNetworkContainerIdentityIsObserverOnly(t *testing.T) {
	index := cache.NewIndexer(cache.MetaNamespaceKeyFunc, Indexers())
	c := &Cache{index: index, synced: func() bool { return true }}
	p := pod("host", "10.0.0.1")
	p.Spec.HostNetwork = true
	p.Status.ContainerStatuses = []core.ContainerStatus{{ContainerID: "containerd://abc"}}
	if err := index.Add(p); err != nil {
		t.Fatal(err)
	}
	o := flow.Observation{Flow: flow.FlowKey{Source: flow.Endpoint{Address: "10.0.0.1"}}, Process: &flow.Process{ContainerID: "abc"}}
	c.Enrich(&o)
	if o.ObserverPod == nil || o.ObserverPod.UID != "host" {
		t.Fatalf("unique container must resolve observer: %+v", o)
	}
	if o.SourcePod != nil || o.DestinationPod != nil {
		t.Fatal("host network IP must not identify canonical endpoint")
	}
}

func TestIPLifecycle(t *testing.T) {
	index := cache.NewIndexer(cache.MetaNamespaceKeyFunc, Indexers())
	c := &Cache{index: index, synced: func() bool { return true }}
	p := pod("old", "10.0.0.1")
	if err := index.Add(p); err != nil {
		t.Fatal(err)
	}
	o := flow.Observation{ObservedAt: time.Now(), Flow: flow.FlowKey{Source: flow.Endpoint{Address: "10.0.0.1"}}}
	c.Enrich(&o)
	if o.SourcePod == nil || o.SourcePod.UID != "old" {
		t.Fatalf("missing UID: %+v", o)
	}
	p2 := p.DeepCopy()
	p2.Status.PodIP = "10.0.0.2"
	if err := index.Update(p2); err != nil {
		t.Fatal(err)
	}
	c.Enrich(&o)
	if o.SourcePod != nil {
		t.Fatal("old IP still indexed")
	}
	if err := index.Delete(p2); err != nil {
		t.Fatal(err)
	}
	if err := index.Add(pod("new", "10.0.0.1")); err != nil {
		t.Fatal(err)
	}
	c.Enrich(&o)
	if o.SourcePod == nil || o.SourcePod.UID != "new" {
		t.Fatal("reuse missing")
	}
}
