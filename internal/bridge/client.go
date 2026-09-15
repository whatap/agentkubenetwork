// Package bridge submits completed SRTT windows to a loopback node queue.
// Acceptance is not backend persistence; requests are never retried.
package bridge

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/whatap/agentkubenetwork/internal/flow"
	xio "github.com/whatap/golib/io"
	"github.com/whatap/golib/lang/value"
	"io"
	"net"
	"net/netip"
	"time"
)

var (
	ErrPartialWindow     = errors.New("partial window")
	ErrNoSamples         = errors.New("no SRTT samples")
	ErrRejected          = errors.New("node queue rejected request")
	ErrAmbiguousDelivery = errors.New("ambiguous delivery; do not retry")
)

type Client struct {
	address string
	timeout time.Duration
}

func NewClient(address string, timeout time.Duration) (*Client, error) {
	a, e := netip.ParseAddrPort(address)
	if e != nil || !a.Addr().IsLoopback() || a.Addr().Zone() != "" || a.Port() == 0 || timeout <= 0 {
		return nil, errors.New("literal loopback address, nonzero port and positive timeout required")
	}
	return &Client{address, timeout}, nil
}
func RequestForWindow(w flow.Window) (*value.MapValue, error) {
	if w.SchemaVersion != flow.SchemaVersion {
		return nil, errors.New("unsupported window schema")
	}
	if w.Partial {
		return nil, ErrPartialWindow
	}
	if w.RTT.Count == 0 {
		return nil, ErrNoSamples
	}
	if e := validateWindow(w); e != nil {
		return nil, e
	}
	m := value.NewMapValue()
	m.PutString("cmd", "uploadNetworkEdge")
	m.PutString("schema", "network.edge.window/v1alpha1")
	m.PutLong("window_start_ms", w.WindowStart.UnixMilli())
	m.PutLong("window_end_ms", w.WindowEnd.UnixMilli())
	m.PutString("observer_node", w.Flow.NodeName)
	m.PutString("protocol", w.Flow.Protocol)
	m.PutString("src_addr", w.Flow.Source.Address)
	m.PutLong("src_port", int64(w.Flow.Source.Port))
	m.PutString("dst_addr", w.Flow.Destination.Address)
	m.PutLong("dst_port", int64(w.Flow.Destination.Port))
	role := "unknown"
	if w.Flow.Direction == "egress" {
		role = "source"
	} else if w.Flow.Direction == "ingress" {
		role = "destination"
	}
	m.PutString("observer_role", role)
	m.PutLong("srtt_count", int64(w.RTT.Count))
	m.PutLong("srtt_sum_us", int64(w.RTT.SumMicros))
	m.PutLong("srtt_min_us", int64(w.RTT.MinMicros))
	m.PutLong("srtt_max_us", int64(w.RTT.MaxMicros))
	if w.Process != nil {
		p := *w.Process
		p.Cmdline = ""
		w.Process = &p
		if p.ContainerID != "" {
			m.PutString("observer_container_id", p.ContainerID)
		}
	}
	for _, r := range []struct {
		prefix string
		ep     *flow.ResolvedEndpoint
	}{{"src", w.SourceResolved}, {"dst", w.DestinationResolved}} {
		if r.ep != nil {
			m.PutString(r.prefix+"_resolved_addr", r.ep.Address)
			m.PutLong(r.prefix+"_resolved_port", int64(r.ep.Port))
			m.PutString(r.prefix+"_resolution_via", r.ep.Via)
		}
	}
	snapshot, e := json.Marshal(w)
	if e != nil {
		return nil, e
	}
	digest := sha256.Sum256(snapshot)
	m.PutString("request_id", hex.EncodeToString(digest[:]))
	return m, nil
}
func (c *Client) Send(ctx context.Context, w flow.Window) error {
	m, e := RequestForWindow(w)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	conn, e := (&net.Dialer{}).DialContext(ctx, "tcp", c.address)
	if e != nil {
		return e
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if e = conn.SetDeadline(deadline); e != nil {
		return e
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	b := value.WriteValue(xio.NewDataOutputX(), m).ToByteArray()
	if len(b) < 1 || len(b) > 65536 {
		return errors.New("request body out of bounds")
	}
	if e := preflightMap(b); e != nil {
		return e
	}
	h := make([]byte, 6)
	binary.BigEndian.PutUint16(h, 0xcafe)
	binary.BigEndian.PutUint32(h[2:], uint32(len(b)))
	payload := append(h, b...)
	for len(payload) > 0 {
		n, err := conn.Write(payload)
		if err != nil {
			return fmt.Errorf("%w: write: %w", ErrAmbiguousDelivery, err)
		}
		if n == 0 {
			return fmt.Errorf("%w: short write", ErrAmbiguousDelivery)
		}
		payload = payload[n:]
	}
	_, e = readAck(conn, m.GetString("request_id"))
	if e != nil {
		if errors.Is(e, ErrRejected) {
			return e
		}
		return fmt.Errorf("%w: %w", ErrAmbiguousDelivery, e)
	}
	return nil
}
func readAck(r io.Reader, id string) (*value.MapValue, error) {
	h := make([]byte, 6)
	if _, e := io.ReadFull(r, h); e != nil {
		return nil, e
	}
	n := int32(binary.BigEndian.Uint32(h[2:]))
	if binary.BigEndian.Uint16(h) != 0xcafe || n < 1 || n > 4096 {
		return nil, errors.New("invalid ACK frame")
	}
	b := make([]byte, int(n))
	if _, e := io.ReadFull(r, b); e != nil {
		return nil, e
	}
	if e := preflightMap(b); e != nil {
		return nil, e
	}
	m := value.ReadMapValue(xio.NewDataInputX(b))
	if m == nil || m.GetString("request_id") != id || m.GetString("stage") != "node_queue" {
		return nil, errors.New("invalid ACK")
	}
	types := map[string]byte{"request_id": 50, "ok": 10, "stage": 50, "now": 20}
	for k, typ := range types {
		v := m.Get(k)
		if v == nil || v.GetValueType() != typ {
			return nil, errors.New("invalid ACK field type")
		}
	}
	keys := m.Keys()
	for keys.HasMoreElements() {
		k := keys.NextString()
		if _, ok := types[k]; !ok && k != "code" {
			return nil, errors.New("unknown ACK key")
		}
	}
	if m.GetLong("now") <= 0 || m.GetLong("now") > maxSafe {
		return nil, errors.New("invalid ACK time")
	}
	if m.GetBool("ok") {
		if m.ContainsKey("code") || m.Size() != 4 {
			return nil, errors.New("success ACK with code")
		}
	} else {
		code := m.Get("code")
		if code == nil || code.GetValueType() != 50 || !token.MatchString(m.GetString("code")) || m.Size() != 5 {
			return nil, errors.New("invalid rejection ACK")
		}
		return nil, fmt.Errorf("%w: %s", ErrRejected, m.GetString("code"))
	}
	return m, nil
}
