package podidentity

import (
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
	apps "k8s.io/api/apps/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func observedFrom(c *Cache, at time.Time) *flow.Pod {
	o := flow.Observation{ObservedAt: at, Flow: flow.FlowKey{Source: flow.Endpoint{Address: "10.0.0.1"}}}
	c.Enrich(&o)
	return o.SourcePod
}

func TestWorkloadMetadataCannotBackfillOlderEvents(t *testing.T) {
	p := workloadPod()
	p.OwnerReferences = []meta.OwnerReference{controller("apps/v1", "DaemonSet", "agent", "old-uid")}
	c := workloadTestCache(t, p)
	for _, at := range []time.Time{{}, time.Unix(19, 0)} {
		assertWorkload(t, observedFrom(c, at), "", "", "")
	}
	original := observedFrom(c, time.Unix(30, 0))
	assertWorkload(t, original, "old-uid", "agent", "DaemonSet")

	changed := p.DeepCopy()
	changed.OwnerReferences[0] = controller("apps/v1", "DaemonSet", "agent", "new-uid")
	if err := c.index.Update(changed); err != nil {
		t.Fatal(err)
	}
	// The informer index may advance before its metadata callback. Do not
	// attach the previous controller to the changed current Pod in that gap.
	assertWorkload(t, observedFrom(c, time.Unix(41, 0)), "", "", "")
	c.workloads.observe("Pod", changed, time.Unix(40, 0))
	assertWorkload(t, observedFrom(c, time.Unix(30, 0)), "", "", "")
	assertWorkload(t, observedFrom(c, time.Unix(41, 0)), "new-uid", "agent", "DaemonSet")
	assertWorkload(t, original, "old-uid", "agent", "DaemonSet")

	// Unrelated metadata/status churn must not move the ownership time bound.
	statusOnly := changed.DeepCopy()
	statusOnly.Labels = map[string]string{"status": "changed"}
	statusOnly.ResourceVersion = "9000"
	if err := c.index.Update(statusOnly); err != nil {
		t.Fatal(err)
	}
	c.workloads.observe("Pod", statusOnly, time.Unix(50, 0))
	assertWorkload(t, observedFrom(c, time.Unix(45, 0)), "new-uid", "agent", "DaemonSet")
}

func TestParentOwnershipCannotBackfillOlderEvents(t *testing.T) {
	p := workloadPod()
	p.OwnerReferences = []meta.OwnerReference{controller("apps/v1", "ReplicaSet", "rs", "rs-uid")}
	c := workloadTestCache(t, p)
	rs := &apps.ReplicaSet{ObjectMeta: meta.ObjectMeta{Name: "rs", Namespace: "ns", UID: "rs-uid", CreationTimestamp: meta.NewTime(time.Unix(5, 0)), OwnerReferences: []meta.OwnerReference{controller("apps/v1", "Deployment", "app", "old-deployment")}}}
	c.workloads.observe("ReplicaSet", rs, time.Unix(40, 0))
	assertWorkload(t, observedFrom(c, time.Unix(30, 0)), "", "", "")
	original := observedFrom(c, time.Unix(41, 0))
	assertWorkload(t, original, "old-deployment", "app", "Deployment")

	changed := rs.DeepCopy()
	changed.OwnerReferences[0].UID = "new-deployment"
	c.workloads.observe("ReplicaSet", changed, time.Unix(50, 0))
	assertWorkload(t, observedFrom(c, time.Unix(45, 0)), "", "", "")
	assertWorkload(t, observedFrom(c, time.Unix(51, 0)), "new-deployment", "app", "Deployment")
	assertWorkload(t, original, "old-deployment", "app", "Deployment")
	changed.ResourceVersion = "999"
	c.workloads.observe("ReplicaSet", changed, time.Unix(60, 0))
	assertWorkload(t, observedFrom(c, time.Unix(55, 0)), "new-deployment", "app", "Deployment")
}

func TestWorkloadsDoNotReattachStalePod(t *testing.T) {
	p := workloadPod()
	p.OwnerReferences = []meta.OwnerReference{controller("apps/v1", "StatefulSet", "db", "db-uid")}
	c := workloadTestCache(t, p)
	original := observedFrom(c, time.Unix(30, 0))
	recreated := p.DeepCopy()
	recreated.UID = "new-pod-uid"
	recreated.CreationTimestamp = meta.NewTime(time.Unix(40, 0))
	c.workloads.observe("Pod", recreated, time.Unix(40, 0))
	assertWorkload(t, observedFrom(c, time.Unix(30, 0)), "", "", "")
	if err := c.index.Update(recreated); err != nil {
		t.Fatal(err)
	}
	if got := observedFrom(c, time.Unix(30, 0)); got != nil {
		t.Fatalf("reattached new Pod to event before its creation: %+v", got)
	}
	assertWorkload(t, original, "db-uid", "db", "StatefulSet")
}
