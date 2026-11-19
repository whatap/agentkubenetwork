package topology

import (
	"fmt"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
)

func workloadPod(name string) *flow.Pod {
	return &flow.Pod{UID: name + "-pod", Name: name + "-replica", Namespace: "apps",
		WorkloadUID: name + "-uid", WorkloadName: name, WorkloadKind: "Deployment"}
}

func TestWorkloadReplicasCoalesceWithoutPodPortOrObserverIdentity(t *testing.T) {
	a, err := New(Config{ClusterID: "cluster-a", WindowSize: time.Minute, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2000; i++ {
		w := testWindow(testStart.Add(time.Duration(i) * time.Millisecond))
		w.SourcePod, w.DestinationPod = workloadPod("client"), workloadPod("server")
		w.SourcePod.UID, w.DestinationPod.UID = fmt.Sprintf("client-%d", i), fmt.Sprintf("server-%d", i)
		w.SourcePod.Name, w.DestinationPod.Name = w.SourcePod.UID, w.DestinationPod.UID
		w.Flow.Source.Address, w.Flow.Destination.Address = fmt.Sprintf("10.1.%d.%d", i/250, i%250+1), fmt.Sprintf("10.2.%d.%d", i/250, i%250+1)
		w.Flow.Source.Port, w.Flow.Destination.Port = uint16(20000+i), uint16(10000+i)
		w.Flow.NodeName = fmt.Sprintf("node-%d", i)
		w.Process = &flow.Process{PID: uint32(i + 1), ContainerID: fmt.Sprintf("container-%d", i)}
		if i%2 == 1 {
			w.SourcePod, w.DestinationPod = w.DestinationPod, w.SourcePod
			w.Flow.Source, w.Flow.Destination = w.Flow.Destination, w.Flow.Source
		}
		if err := a.ObserveWindow(w); err != nil {
			t.Fatalf("replica %d: %v", i, err)
		}
		// The aggregation must not retain mutable identity pointers.
		w.SourcePod.WorkloadName = "mutated-after-observation"
	}
	got := a.FlushAll()
	if len(got) != 1 {
		t.Fatalf("replicas became %d relationships", len(got))
	}
	s := got[0]
	if s.Source != (Endpoint{Kind: "Deployment", Namespace: "apps", Name: "client", UID: "client-uid"}) || s.Destination != (Endpoint{Kind: "Deployment", Namespace: "apps", Name: "server", UID: "server-uid"}) {
		t.Fatalf("wrong workload endpoints: %+v", s)
	}
	if s.DestinationPort != 0 || s.Direction != DirectionUnknown || !s.Observed || s.ResultObserved || s.ErrorObserved || s.LastSeenMS != testStart.Add(1999*time.Millisecond).UnixMilli() {
		t.Fatalf("invented transport result: %+v", s)
	}
}

func TestMissingOwnerStaysUnresolvedAndNeverBackfillsFirstIdentity(t *testing.T) {
	for name, pod := range map[string]*flow.Pod{
		"nil pod":           nil,
		"pod only":          {UID: "pod-uid", Namespace: "apps", Name: "pod-name"},
		"missing uid":       {WorkloadName: "client", WorkloadKind: "Deployment", Namespace: "apps"},
		"missing name":      {WorkloadUID: "wl-uid", WorkloadKind: "Deployment", Namespace: "apps"},
		"missing kind":      {WorkloadUID: "wl-uid", WorkloadName: "client", Namespace: "apps"},
		"missing namespace": {WorkloadUID: "wl-uid", WorkloadName: "client", WorkloadKind: "Deployment"},
	} {
		t.Run(name, func(t *testing.T) {
			a, err := New(Config{ClusterID: "cluster-a", WindowSize: time.Minute, MaxEntries: 2})
			if err != nil {
				t.Fatal(err)
			}
			w := testWindow(testStart.Add(time.Second))
			w.SourcePod, w.DestinationPod = pod, workloadPod("server")
			w.SourceResolved = &flow.ResolvedEndpoint{Address: "10.20.1.2", Port: 45000, Via: "conntrack"}
			if err := a.ObserveWindow(w); err != nil {
				t.Fatal(err)
			}
			w.SourcePod = workloadPod("client")
			if err := a.ObserveWindow(w); err != nil {
				t.Fatal(err)
			}
			got := a.FlushAll()
			if len(got) != 2 {
				t.Fatalf("later identity overwrote the first observation: %+v", got)
			}
			var unresolved *Endpoint
			for _, s := range got {
				for _, endpoint := range []Endpoint{s.Source, s.Destination} {
					if endpoint.Kind == KindUnresolvedAddress {
						copy := endpoint
						unresolved = &copy
					}
				}
			}
			if unresolved == nil || *unresolved != (Endpoint{Kind: KindUnresolvedAddress, Address: "10.20.1.2"}) {
				t.Fatalf("invented identity/external endpoint: %+v", got)
			}
		})
	}
}
