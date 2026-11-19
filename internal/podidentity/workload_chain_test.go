package podidentity

import (
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
	apps "k8s.io/api/apps/v1"
	batch "k8s.io/api/batch/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestWorkloadControllerChain(t *testing.T) {
	for _, chain := range []struct{ apiVersion, kind, topVersion, topKind string }{
		{"apps/v1", "ReplicaSet", "apps/v1", "Deployment"},
		{"batch/v1", "Job", "batch/v1", "CronJob"},
	} {
		t.Run(chain.kind, func(t *testing.T) {
			for _, scenario := range []string{"owned", "standalone", "missing", "wrong-uid", "wrong-namespace", "wrong-name", "no-controller", "missing-uid", "multiple-controllers", "unsupported-owner", "wrong-owner-api", "parent-newer-than-event"} {
				t.Run(scenario, func(t *testing.T) {
					p := workloadPod()
					p.OwnerReferences = []meta.OwnerReference{controller(chain.apiVersion, chain.kind, "parent", "parent-uid")}
					c := workloadTestCache(t, p)
					m := meta.ObjectMeta{Name: "parent", Namespace: "ns", UID: "parent-uid", CreationTimestamp: meta.NewTime(time.Unix(5, 0)), OwnerReferences: []meta.OwnerReference{controller(chain.topVersion, chain.topKind, "top", "top-uid")}}
					switch scenario {
					case "standalone":
						m.OwnerReferences = nil
					case "wrong-uid":
						m.UID = "recreated-parent"
					case "wrong-namespace":
						m.Namespace = "another-namespace"
					case "wrong-name":
						m.Name = "another-name"
					case "no-controller":
						m.OwnerReferences[0].Controller = nil
					case "missing-uid":
						m.OwnerReferences[0].UID = ""
					case "multiple-controllers":
						m.OwnerReferences = append(m.OwnerReferences, controller(chain.topVersion, chain.topKind, "other", "other-uid"))
					case "unsupported-owner":
						m.OwnerReferences[0] = controller("apps/v1", "StatefulSet", "db", "db-uid")
					case "wrong-owner-api":
						m.OwnerReferences[0].APIVersion = "custom.example/v1"
					case "parent-newer-than-event":
						m.CreationTimestamp = meta.NewTime(time.Unix(40, 0))
					}
					if scenario != "missing" {
						var parent meta.Object = &apps.ReplicaSet{ObjectMeta: m}
						if chain.kind == "Job" {
							parent = &batch.Job{ObjectMeta: m}
						}
						c.workloads.observe(chain.kind, parent, time.Unix(20, 0))
					}
					o := flow.Observation{ObservedAt: time.Unix(30, 0), Flow: flow.FlowKey{Source: flow.Endpoint{Address: "10.0.0.1"}}}
					c.Enrich(&o)
					switch scenario {
					case "owned":
						assertWorkload(t, o.SourcePod, "top-uid", "top", chain.topKind)
					case "standalone":
						assertWorkload(t, o.SourcePod, "parent-uid", "parent", chain.kind)
					default:
						assertWorkload(t, o.SourcePod, "", "", "")
					}
				})
			}
		})
	}
}

func TestDirectWorkloadOwnerValidation(t *testing.T) {
	for _, scenario := range []string{"StatefulSet", "DaemonSet", "Deployment", "CronJob", "ReplicationController", "bare-pod", "nil-controller", "false-controller", "missing-uid", "missing-name", "multiple-controllers", "wrong-api", "unsupported-kind"} {
		t.Run(scenario, func(t *testing.T) {
			p := workloadPod()
			p.OwnerReferences = []meta.OwnerReference{controller("apps/v1", "StatefulSet", "workload", "workload-uid")}
			known := true
			switch scenario {
			case "StatefulSet", "DaemonSet", "Deployment":
				p.OwnerReferences[0].Kind = scenario
			case "CronJob":
				p.OwnerReferences[0] = controller("batch/v1", scenario, "workload", "workload-uid")
			case "ReplicationController":
				p.OwnerReferences[0] = controller("v1", scenario, "workload", "workload-uid")
			default:
				known = false
				switch scenario {
				case "bare-pod":
					p.OwnerReferences = nil
				case "nil-controller":
					p.OwnerReferences[0].Controller = nil
				case "false-controller":
					*p.OwnerReferences[0].Controller = false
				case "missing-uid":
					p.OwnerReferences[0].UID = ""
				case "missing-name":
					p.OwnerReferences[0].Name = ""
				case "multiple-controllers":
					p.OwnerReferences = append(p.OwnerReferences, controller("apps/v1", "DaemonSet", "other", "other-uid"))
				case "wrong-api":
					p.OwnerReferences[0].APIVersion = "custom.example/v1"
				case "unsupported-kind":
					p.OwnerReferences[0].Kind = "CustomController"
				}
			}
			c := workloadTestCache(t, p)
			o := flow.Observation{ObservedAt: time.Unix(30, 0), Flow: flow.FlowKey{Source: flow.Endpoint{Address: "10.0.0.1"}}}
			c.Enrich(&o)
			if known {
				assertWorkload(t, o.SourcePod, "workload-uid", "workload", scenario)
			} else {
				assertWorkload(t, o.SourcePod, "", "", "")
			}
		})
	}
}
