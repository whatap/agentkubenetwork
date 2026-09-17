// Package podidentity enriches L4 observations from a current Pod informer cache.
package podidentity

import (
	"github.com/whatap/agentkubenetwork/internal/flow"
	core "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"net/netip"
	"strings"
	"time"
)

type Cache struct {
	index  cache.Indexer
	synced func() bool
}

func Indexers() cache.Indexers {
	return cache.Indexers{"ip": func(obj any) ([]string, error) {
		p := obj.(*core.Pod)
		keys := map[string]bool{}
		keys[ipKey(p.Status.PodIP)] = true
		for _, ip := range p.Status.PodIPs {
			keys[ipKey(ip.IP)] = true
		}
		return nonempty(keys), nil
	}, "container": func(obj any) ([]string, error) {
		p := obj.(*core.Pod)
		keys := map[string]bool{}
		for _, statuses := range [][]core.ContainerStatus{p.Status.ContainerStatuses, p.Status.InitContainerStatuses, p.Status.EphemeralContainerStatuses} {
			for _, s := range statuses {
				keys[containerKey(s.ContainerID)] = true
			}
		}
		return nonempty(keys), nil
	}}
}
func nonempty(keys map[string]bool) []string {
	var out []string
	for k := range keys {
		if k != "" {
			out = append(out, k)
		}
	}
	return out
}
func ipKey(s string) string {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return ""
	}
	return a.Unmap().String()
}
func containerKey(s string) string {
	if _, id, ok := strings.Cut(s, "://"); ok {
		return id
	}
	return s
}
func (c *Cache) lookup(index, key string, at time.Time) *flow.Pod {
	if key == "" || !c.synced() {
		return nil
	}
	objects, err := c.index.ByIndex(index, key)
	if err != nil || len(objects) != 1 {
		return nil
	}
	p := objects[0].(*core.Pod)
	// Host-network IPs are shared, but a unique container still identifies its observer.
	if p.UID == "" || (index == "ip" && p.Spec.HostNetwork) || (!at.IsZero() && !p.CreationTimestamp.IsZero() && at.Before(p.CreationTimestamp.Time)) {
		return nil
	}
	return &flow.Pod{UID: string(p.UID), Namespace: p.Namespace, Name: p.Name}
}
func (c *Cache) Enrich(o *flow.Observation) {
	source, destination := o.Flow.Source.Address, o.Flow.Destination.Address
	if o.SourceResolved != nil {
		source = o.SourceResolved.Address
	}
	if o.DestinationResolved != nil {
		destination = o.DestinationResolved.Address
	}
	o.ObserverPod = nil
	if o.Process != nil {
		o.ObserverPod = c.lookup("container", containerKey(o.Process.ContainerID), o.ObservedAt)
	}
	o.SourcePod = c.lookup("ip", ipKey(source), o.ObservedAt)
	o.DestinationPod = c.lookup("ip", ipKey(destination), o.ObservedAt)
}
