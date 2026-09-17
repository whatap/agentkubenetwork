package tagcount

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/whatap/agentkubenetwork/internal/dns"
	"github.com/whatap/agentkubenetwork/internal/flow"
	"github.com/whatap/agentkubenetwork/internal/l7"
	"github.com/whatap/golib/lang/pack"
	"github.com/whatap/golib/lang/value"
)

const HTTPCategory = "kube_network_http_v1alpha1"
const DNSCategory = "kube_network_dns_v1alpha1"

// PackForL7 preserves one HTTP observation, not an aggregated percentile.
// HTTP/1 completes at the final response status line; HTTP/2 at response
// headers. Neither boundary includes response-body completion.
func PackForL7(t l7.Transaction, pcode int64, oid int32) (*pack.TagCountPack, error) {
	if !validEventEnvelope(t.ObservedAt, t.Flow.NodeName, t.ObserverPID, t.Process, pcode, oid) ||
		t.SchemaVersion != l7.SchemaVersion || t.Flow.Protocol != "tcp" || t.Flow.Direction != "client-to-server" ||
		(t.Protocol != l7.ProtocolHTTP1 && t.Protocol != l7.ProtocolHTTP2) ||
		(t.Source != l7.SourceKernelPlaintext && t.Source != l7.SourceOpenSSL) ||
		!validHTTPBoundary(t) || t.StatusCode < 200 || t.StatusCode > 599 ||
		t.ResponseLatencyMicros > math.MaxInt64 || !validHTTPMethod(t.Method) ||
		(t.Protocol == l7.ProtocolHTTP1 && t.StreamID != 0) ||
		(t.Protocol == l7.ProtocolHTTP2 && t.StreamID == 0) || t.StreamID > math.MaxInt32 ||
		!validEventEndpoint(t.Flow.Source) || !validEventEndpoint(t.Flow.Destination) ||
		!validEventResolved(t.SourceResolved) || !validEventResolved(t.DestinationResolved) {
		return nil, errors.New("invalid HTTP observation or pack identity")
	}
	p := pack.NewTagCountPack()
	p.Pcode, p.Oid, p.Time, p.Category = pcode, oid, t.ObservedAt.UnixMilli(), HTTPCategory
	p.Tags.PutString("schema", t.SchemaVersion)
	p.Tags.PutString("observer_node", t.Flow.NodeName)
	p.Tags.PutString("protocol", t.Protocol)
	p.Tags.PutString("source", string(t.Source))
	p.Tags.PutString("src_addr", t.Flow.Source.Address)
	p.Tags.PutString("dst_addr", t.Flow.Destination.Address)
	p.Tags.PutString("http_method", t.Method)
	p.Tags.PutString("latency_boundary", t.LatencyBoundary)
	p.Data.PutLong("src_port", int64(t.Flow.Source.Port))
	p.Data.PutLong("dst_port", int64(t.Flow.Destination.Port))
	p.Data.PutLong("observed_at_ms", p.Time)
	p.Data.PutLong("http_status", int64(t.StatusCode))
	p.Data.PutLong("latency_us", int64(t.ResponseLatencyMicros))
	p.Data.PutLong("transaction_count", 1)
	putEventObserver(p, t.ObserverPID, t.Process)
	putEventResolved(p, "src", t.SourceResolved)
	putEventResolved(p, "dst", t.DestinationResolved)
	putEventPod(p, "src", t.SourcePod)
	putEventPod(p, "dst", t.DestinationPod)
	putEventPod(p, "observer", t.ObserverPod)
	if t.StreamID != 0 {
		p.Data.PutLong("stream_id", int64(t.StreamID))
	}
	p.Tags.PutString("record_id", eventRecordID(p, t.ObservedAt, t.Process))
	return p, nil
}

func validHTTPBoundary(t l7.Transaction) bool {
	return (t.Protocol == l7.ProtocolHTTP1 && t.LatencyBoundary == l7.BoundaryResponseStatus) ||
		(t.Protocol == l7.ProtocolHTTP2 && t.LatencyBoundary == l7.BoundaryResponseHeaders)
}

// PackForDNS preserves each DNS transaction independently for exact response
// latency distributions; it does not compute a percentile from count/sum.
func PackForDNS(t dns.Transaction, pcode int64, oid int32) (*pack.TagCountPack, error) {
	if !validEventEnvelope(t.ObservedAt, t.NodeName, t.ObserverPID, t.Process, pcode, oid) ||
		t.SchemaVersion != dns.SchemaVersion || t.Protocol != "udp" ||
		!validDNSObservedEndpoint(t.Client) || !validDNSObservedEndpoint(t.Server) ||
		!validEventResolved(t.ClientResolved) || !validEventResolved(t.ServerResolved) ||
		!dns.ValidQuestionName(t.QueryName) ||
		(t.QueryType != "" && !eventASCII(t.QueryType, 32)) ||
		(t.ResponseCode != "" && !eventASCII(t.ResponseCode, 16)) || t.LatencyMicros > math.MaxInt64 {
		return nil, errors.New("invalid DNS observation or pack identity")
	}
	switch t.Outcome {
	case dns.OutcomeResponse, dns.OutcomeNoResponse, dns.OutcomeParseError, dns.OutcomeIncomplete:
	default:
		return nil, errors.New("invalid DNS outcome")
	}
	if !t.LatencyMeasured && t.LatencyMicros != 0 {
		return nil, errors.New("DNS latency value without measurement")
	}
	if t.Outcome != dns.OutcomeResponse && (t.ResponseCode != "" || t.LatencyMeasured || t.LatencyMicros != 0) {
		return nil, errors.New("DNS response metadata without a response")
	}
	if t.Reason != "" && (t.Outcome != dns.OutcomeIncomplete || (t.Reason != dns.ReasonCaptureEnded && t.Reason != dns.ReasonStateCapacity)) {
		return nil, errors.New("invalid DNS completion reason")
	}
	p := pack.NewTagCountPack()
	p.Pcode, p.Oid, p.Time, p.Category = pcode, oid, t.ObservedAt.UnixMilli(), DNSCategory
	p.Tags.PutString("schema", t.SchemaVersion)
	p.Tags.PutString("observer_node", t.NodeName)
	p.Tags.PutString("protocol", t.Protocol)
	p.Tags.PutString("client_addr", t.Client.Address)
	p.Tags.PutString("server_addr", t.Server.Address)
	if t.QueryName != "" {
		p.Tags.PutString("query_name", t.QueryName)
	}
	if t.QueryType != "" {
		p.Tags.PutString("query_type", t.QueryType)
	}
	p.Tags.PutString("outcome", t.Outcome)
	if t.Reason != "" {
		p.Tags.PutString("reason", t.Reason)
	}
	if t.ResponseCode != "" {
		p.Tags.PutString("rcode", t.ResponseCode)
	}
	p.Data.PutLong("client_port", int64(t.Client.Port))
	p.Data.PutLong("server_port", int64(t.Server.Port))
	p.Data.PutLong("observed_at_ms", p.Time)
	p.Data.PutLong("transaction_count", 1)
	p.Data.PutLong("response_count", 0)
	if t.Outcome == dns.OutcomeResponse {
		p.Data.PutLong("response_count", 1)
	}
	if t.LatencyMeasured {
		p.Data.PutLong("latency_us", int64(t.LatencyMicros))
	}
	putEventObserver(p, t.ObserverPID, t.Process)
	putEventResolved(p, "client", t.ClientResolved)
	putEventResolved(p, "server", t.ServerResolved)
	putEventPod(p, "client", t.ClientPod)
	putEventPod(p, "server", t.ServerPod)
	putEventPod(p, "observer", t.ObserverPod)
	p.Tags.PutString("record_id", eventRecordID(p, t.ObservedAt, t.Process))
	return p, nil
}

// DNS may retain a wildcard or not-yet-bound socket tuple as diagnostic
// evidence. It must never be promoted to a resolved Pod or a complete edge.
func validDNSObservedEndpoint(endpoint flow.Endpoint) bool {
	address, err := netip.ParseAddr(endpoint.Address)
	return err == nil && address.Zone() == ""
}

// Validate before any signed numeric conversion or wire serialization.
func validEventEnvelope(observed time.Time, node string, pid uint32, process *flow.Process, pcode int64, oid int32) bool {
	sec, subMS := observed.Unix(), int64(observed.Nanosecond())/int64(time.Millisecond)
	if pcode <= 0 || oid == 0 || sec < 0 || sec > (math.MaxInt64-subMS)/1000 ||
		observed.UnixMilli() <= 0 || !eventASCII(node, 253) {
		return false
	}
	if process != nil {
		if pid != 0 && process.PID != 0 && pid != process.PID {
			return false
		}
		if process.ContainerID != "" && !eventASCII(process.ContainerID, 128) {
			return false
		}
	}
	return true
}

func eventASCII(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 33 || s[i] > 126 {
			return false
		}
	}
	return true
}

func validEventEndpoint(e flow.Endpoint) bool {
	ip, err := netip.ParseAddr(e.Address)
	return err == nil && ip.Zone() == "" && !ip.IsUnspecified() && !ip.IsMulticast() && e.Port != 0
}

var eventResolutionVia = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,32}$`)

func validEventResolved(r *flow.ResolvedEndpoint) bool {
	return r == nil || (validEventEndpoint(flow.Endpoint{Address: r.Address, Port: r.Port}) && eventResolutionVia.MatchString(r.Via))
}

func validHTTPMethod(method string) bool {
	switch method {
	case "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT":
		return true
	}
	return false
}

// eventRecordID hashes only the scalar allowlists already copied into the pack.
// Length framing and sorted keys make it independent of insertion order. Seconds
// plus nanoseconds retain sub-ms identity without overflowing UnixNano. Identical
// observations dedupe; no random UID or private path/process text enters the hash.
func eventRecordID(p *pack.TagCountPack, observed time.Time, process *flow.Process) string {
	h := sha256.New()
	field := func(s string) { fmt.Fprintf(h, "%d:%s", len(s), s) }
	field(p.Category)
	field(strconv.FormatInt(p.Pcode, 10))
	field(strconv.FormatInt(int64(p.Oid), 10))
	field(strconv.FormatInt(observed.Unix(), 10))
	field(strconv.Itoa(observed.Nanosecond()))
	var start uint64
	if process != nil {
		start = process.StartTimeTicks
	}
	field(strconv.FormatUint(start, 10))
	for _, m := range []*value.MapValue{p.Tags, p.Data} {
		keys := make([]string, 0, m.Size())
		iter := m.Keys()
		for iter.HasMoreElements() {
			keys = append(keys, iter.NextString())
		}
		sort.Strings(keys)
		field(strconv.Itoa(len(keys)))
		for _, k := range keys {
			field(k)
			if m == p.Tags {
				field(m.GetString(k))
			} else {
				field(strconv.FormatInt(m.GetLong(k), 10))
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func putEventObserver(p *pack.TagCountPack, pid uint32, process *flow.Process) {
	if process != nil {
		if pid == 0 {
			pid = process.PID
		}
		if process.ContainerID != "" {
			p.Tags.PutString("observer_container_id", process.ContainerID)
		}
	}
	if pid != 0 {
		p.Data.PutLong("observer_pid", int64(pid))
	}
}

func putEventResolved(p *pack.TagCountPack, prefix string, r *flow.ResolvedEndpoint) {
	if r == nil {
		return
	}
	p.Tags.PutString(prefix+"_resolved_addr", r.Address)
	p.Tags.PutString(prefix+"_resolution_via", r.Via)
	p.Data.PutLong(prefix+"_resolved_port", int64(r.Port))
}

func putEventPod(p *pack.TagCountPack, prefix string, pod *flow.Pod) {
	if pod == nil || pod.UID == "" {
		return
	}
	p.Tags.PutString(prefix+"_pod_uid", pod.UID)
	p.Tags.PutString(prefix+"_pod_namespace", pod.Namespace)
	p.Tags.PutString(prefix+"_pod_name", pod.Name)
}
