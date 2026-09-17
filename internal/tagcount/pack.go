package tagcount

import (
	"errors"
	"github.com/whatap/agentkubenetwork/internal/bridge"
	"github.com/whatap/agentkubenetwork/internal/flow"
	"github.com/whatap/golib/lang/pack"
)

const Category = "kube_network_edge_v1alpha1"

var (
	ErrPartialWindow   = bridge.ErrPartialWindow
	ErrNoSamples       = bridge.ErrNoSamples
	ErrIncompleteTuple = bridge.ErrIncompleteTuple
)

// PackForWindow converts a validated window without transport or identity discovery.
func PackForWindow(w flow.Window, pcode int64, oid int32) (*pack.TagCountPack, error) {
	if pcode <= 0 || oid == 0 {
		return nil, errors.New("positive project code and nonzero object ID are required")
	}
	request, err := bridge.RequestForWindow(w)
	if err != nil {
		return nil, err
	}
	p := pack.NewTagCountPack()
	p.Pcode = pcode
	p.Oid = oid
	p.Time = request.GetLong("window_start_ms")
	p.Category = Category
	for _, identity := range []struct {
		prefix string
		pod    *flow.Pod
	}{{"src", w.SourcePod}, {"dst", w.DestinationPod}, {"observer", w.ObserverPod}} {
		if identity.pod != nil && identity.pod.UID != "" {
			p.Tags.PutString(identity.prefix+"_pod_uid", identity.pod.UID)
			p.Tags.PutString(identity.prefix+"_pod_namespace", identity.pod.Namespace)
			p.Tags.PutString(identity.prefix+"_pod_name", identity.pod.Name)
		}
	}
	for _, key := range []string{
		"schema", "observer_node", "protocol", "src_addr", "dst_addr", "observer_role",
		"observer_container_id", "src_resolved_addr", "src_resolution_via", "dst_resolved_addr", "dst_resolution_via",
	} {
		if request.ContainsKey(key) {
			p.Tags.PutString(key, request.GetString(key))
		}
	}
	for _, key := range []string{
		"src_port", "dst_port", "window_start_ms", "window_end_ms",
		"srtt_count", "srtt_sum_us", "srtt_min_us", "srtt_max_us", "src_resolved_port", "dst_resolved_port",
	} {
		if request.ContainsKey(key) {
			p.Data.PutLong(key, request.GetLong(key))
		}
	}
	return p, nil
}
