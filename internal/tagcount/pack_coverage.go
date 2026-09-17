package tagcount

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/whatap/agentkubenetwork/internal/l7"
	"github.com/whatap/golib/lang/pack"
)

const CoverageCategory = "kube_network_coverage_v1alpha1"

// PackForL7Drop exports observation loss, never a service error or a latency.
// reported_count retains the producer's reason-specific counter semantics;
// it is not a count of failed customer requests.
func PackForL7Drop(d l7.Drop, pcode int64, oid int32) (*pack.TagCountPack, error) {
	if pcode <= 0 || oid == 0 {
		return nil, fmt.Errorf("invalid coverage envelope identity")
	}
	if d.SchemaVersion != l7.SchemaVersion || d.Outcome != "drop" {
		return nil, fmt.Errorf("invalid coverage schema or outcome")
	}
	if d.ObservedAt.IsZero() || d.ObservedAt.UnixMilli() <= 0 || d.ObservedAt.Year() > 9999 {
		return nil, fmt.Errorf("invalid coverage observation time")
	}
	if !validCoverageToken(d.NodeName, 253) || !validCoverageToken(d.Reason, 128) {
		return nil, fmt.Errorf("invalid coverage node or reason")
	}
	if d.Source != "" && d.Source != string(l7.SourceKernelPlaintext) && d.Source != string(l7.SourceOpenSSL) {
		return nil, fmt.Errorf("invalid coverage source")
	}
	if d.Protocol != "" && d.Protocol != l7.ProtocolHTTP1 && d.Protocol != l7.ProtocolHTTP2 {
		return nil, fmt.Errorf("invalid coverage protocol")
	}
	if d.Count == 0 || d.Count > (uint64(1)<<53)-1 {
		return nil, fmt.Errorf("invalid coverage count")
	}
	p := pack.NewTagCountPack()
	p.Pcode = pcode
	p.Oid = oid
	p.Time = d.ObservedAt.UnixMilli()
	p.Category = CoverageCategory
	p.Tags.PutString("schema", d.SchemaVersion)
	p.Tags.PutString("observer_node", d.NodeName)
	p.Tags.PutString("outcome", d.Outcome)
	p.Tags.PutString("reason", d.Reason)
	if d.Source != "" {
		p.Tags.PutString("source", d.Source)
	}
	if d.Protocol != "" {
		p.Tags.PutString("protocol", d.Protocol)
	}
	p.Data.PutLong("observed_at_ms", p.Time)
	p.Data.PutLong("coverage_record_count", 1)
	p.Data.PutLong("reported_count", int64(d.Count))
	if d.ObserverPID != 0 {
		p.Data.PutLong("observer_pid", int64(d.ObserverPID))
	}
	// Preserve distinct observations inside one storage millisecond without
	// retaining a raw payload or conflating a repeated request with a retry.
	key, err := json.Marshal([]any{d.SchemaVersion, d.ObservedAt.UTC().Format(time.RFC3339Nano), d.NodeName, d.ObserverPID, d.Protocol, d.Source, d.Reason, d.Count})
	if err != nil {
		return nil, fmt.Errorf("encode coverage identity: %w", err)
	}
	sum := sha256.Sum256(key)
	p.Tags.PutString("record_id", hex.EncodeToString(sum[:]))
	return p, nil
}

func validCoverageToken(value string, limit int) bool {
	if len(value) == 0 || len(value) > limit {
		return false
	}
	for _, c := range value {
		if c <= 32 || c > 126 {
			return false
		}
	}
	return true
}
