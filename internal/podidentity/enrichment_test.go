package podidentity

import (
	"github.com/whatap/agentkubenetwork/internal/flow"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"testing"
	"time"
)

func TestDualStackResolvedObserverAndUnknown(t *testing.T) {
	index := cache.NewIndexer(cache.MetaNamespaceKeyFunc, Indexers())
	synced := true
	c := &Cache{index: index, synced: func() bool { return synced }}
	p := pod("server", "10.0.0.2")
	p.Status.PodIPs = []core.PodIP{{IP: "10.0.0.2"}, {IP: "2001:db8::2"}}
	p.Status.ContainerStatuses = []core.ContainerStatus{{ContainerID: "containerd://abcdef"}}
	p.CreationTimestamp = meta.NewTime(time.Unix(50, 0))
	if err := index.Add(p); err != nil {
		t.Fatal(err)
	}
	o := flow.Observation{ObservedAt: time.Unix(100, 0), Process: &flow.Process{ContainerID: "docker://abcdef"}, Flow: flow.FlowKey{Source: flow.Endpoint{Address: "10.0.0.1"}, Destination: flow.Endpoint{Address: "service"}}, DestinationResolved: &flow.ResolvedEndpoint{Address: "2001:0db8::2"}}
	c.Enrich(&o)
	if o.ObserverPod == nil || o.DestinationPod == nil || o.DestinationPod.UID != "server" || o.SourcePod != nil {
		t.Fatalf("observer not source / resolved dual stack: %+v", o)
	}
	for _, kind := range []string{"unsynced", "predates", "ambiguous"} {
		t.Run(kind, func(t *testing.T) {
			copy := o
			changed := p.DeepCopy()
			synced = true
			switch kind {
			case "unsynced":
				synced = false
			case "predates":
				copy.ObservedAt = time.Unix(49, 0)

			case "ambiguous":
				other := p.DeepCopy()
				other.Name = "other"
				other.UID = "other"
				_ = index.Add(other)
				defer index.Delete(other)
			}
			_ = index.Update(changed)
			defer index.Update(p)
			c.Enrich(&copy)
			if copy.SourcePod != nil || copy.DestinationPod != nil || copy.ObserverPod != nil {
				t.Fatalf("must remain unknown: %+v", copy)
			}
		})
	}
}
