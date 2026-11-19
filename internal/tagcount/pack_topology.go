package tagcount

import (
	"errors"
	"strconv"

	"github.com/whatap/agentkubenetwork/internal/topology"
	"github.com/whatap/golib/lang/pack"
)

const TopologyCategory = "kube_network_topology_v1alpha1"

// PackForTopology snapshots presence evidence, not request counts. Consumers
// must reduce every numeric field with MAX (flags also support OR), never SUM,
// including repeated records, late corrections and observations across OIDs.
func PackForTopology(s topology.Summary, pcode int64, oid int32) (*pack.TagCountPack, error) {
	if pcode <= 0 || oid == 0 {
		return nil, errors.New("positive project code and nonzero object ID are required")
	}
	if err := topology.ValidateSummary(s); err != nil {
		return nil, err
	}
	p := pack.NewTagCountPack()
	p.Pcode, p.Oid, p.Time, p.Category = pcode, oid, s.WindowStart.UnixMilli(), TopologyCategory
	p.Tags.PutString("schema", topology.SchemaVersion)
	p.Tags.PutString("cluster_id", s.ClusterID)
	for _, endpoint := range []struct {
		prefix string
		value  topology.Endpoint
	}{{"src", s.Source}, {"dst", s.Destination}} {
		p.Tags.PutString(endpoint.prefix+"_kind", endpoint.value.Kind)
		if endpoint.value.Kind == topology.KindUnresolvedAddress {
			p.Tags.PutString(endpoint.prefix+"_address", endpoint.value.Address)
		} else {
			p.Tags.PutString(endpoint.prefix+"_uid", endpoint.value.UID)
			p.Tags.PutString(endpoint.prefix+"_name", endpoint.value.Name)
			p.Tags.PutString(endpoint.prefix+"_namespace", endpoint.value.Namespace)
		}
	}
	p.Tags.PutString("transport", s.Transport)
	p.Tags.PutString("protocol", s.Protocol)
	p.Tags.PutString("direction", s.Direction)
	if s.DestinationPort != 0 {
		p.Tags.PutString("dst_port", strconv.FormatUint(uint64(s.DestinationPort), 10))
	}
	for _, flag := range []struct {
		key   string
		value bool
	}{{"observed", s.Observed}, {"result_observed", s.ResultObserved}, {"error_observed", s.ErrorObserved}} {
		var n int64
		if flag.value {
			n = 1
		}
		p.Data.PutLong(flag.key, n)
	}
	p.Data.PutLong("last_seen_ms", s.LastSeenMS)
	p.Data.PutLong("window_start_ms", s.WindowStart.UnixMilli())
	p.Data.PutLong("window_end_ms", s.WindowEnd.UnixMilli())
	return p, nil
}
