package podidentity

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
)

func TestWorkloadSnapshotJSONContract(t *testing.T) {
	const input = `{"uid":"pod-uid","namespace":"ns","name":"pod","workload_uid":"owner-uid","workload_name":"owner","workload_kind":"StatefulSet"}`
	var p flow.Pod
	if err := json.Unmarshal([]byte(input), &p); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"workload_uid": "owner-uid", "workload_name": "owner", "workload_kind": "StatefulSet"} {
		if got[key] != want {
			t.Errorf("%s = %q; want %q", key, got[key], want)
		}
	}
	encoded, err = json.Marshal(flow.Pod{UID: "pod-uid", Namespace: "ns", Name: "pod"})
	if err != nil {
		t.Fatal(err)
	}
	got = nil
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"workload_uid", "workload_name", "workload_kind"} {
		if _, ok := got[key]; ok {
			t.Errorf("unknown workload must omit %s: %s", key, encoded)
		}
	}
}

func controller(apiVersion, kind, name, uid string) meta.OwnerReference {
	controlled := true
	return meta.OwnerReference{APIVersion: apiVersion, Kind: kind, Name: name, UID: types.UID(uid), Controller: &controlled}
}

func workloadPod() *core.Pod {
	p := pod("pod-uid", "10.0.0.1")
	p.CreationTimestamp = meta.NewTime(time.Unix(10, 0))
	p.Status.ContainerStatuses = []core.ContainerStatus{{ContainerID: "containerd://container"}}
	return p
}

func workloadTestCache(t *testing.T, p *core.Pod) *Cache {
	t.Helper()
	index := cache.NewIndexer(cache.MetaNamespaceKeyFunc, Indexers())
	if err := index.Add(p); err != nil {
		t.Fatal(err)
	}
	c := &Cache{index: index, synced: func() bool { return true }, workloads: newWorkloadCache()}
	c.workloads.observe("Pod", p, time.Unix(20, 0))
	return c
}

func assertWorkload(t *testing.T, p *flow.Pod, uid, name, kind string) {
	t.Helper()
	if p == nil || p.UID != "pod-uid" || p.Namespace != "ns" {
		t.Fatalf("lost Pod identity: %+v", p)
	}
	if p.WorkloadUID != uid || p.WorkloadName != name || p.WorkloadKind != kind {
		t.Fatalf("workload = %+v; want %s/%s/%s", p, uid, name, kind)
	}
}

func TestDirectWorkloadOwnerSnapshotIsOptIn(t *testing.T) {
	p := workloadPod()
	p.OwnerReferences = []meta.OwnerReference{controller("apps/v1", "StatefulSet", "db", "statefulset-uid")}
	c := workloadTestCache(t, p)
	o := flow.Observation{ObservedAt: time.Unix(30, 0), Flow: flow.FlowKey{Source: flow.Endpoint{Address: "10.0.0.1"}, Destination: flow.Endpoint{Address: "10.0.0.1"}}, Process: &flow.Process{ContainerID: "container"}}
	c.Enrich(&o)
	for _, got := range []*flow.Pod{o.ObserverPod, o.SourcePod, o.DestinationPod} {
		assertWorkload(t, got, "statefulset-uid", "db", "StatefulSet")
	}
	if o.ObserverPod == o.SourcePod || o.SourcePod == o.DestinationPod {
		t.Fatal("lookup results must be independent value snapshots")
	}
	p.OwnerReferences[0].Name = "changed"
	assertWorkload(t, o.SourcePod, "statefulset-uid", "db", "StatefulSet")
	legacy := &Cache{index: c.index, synced: c.synced}
	legacy.Enrich(&o)
	assertWorkload(t, o.SourcePod, "", "", "")
}
