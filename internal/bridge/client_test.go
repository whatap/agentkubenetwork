package bridge

import (
	"context"
	"encoding/binary"
	"github.com/whatap/agentkubenetwork/internal/flow"
	xio "github.com/whatap/golib/io"
	"github.com/whatap/golib/lang/value"
	"io"
	"net"
	"testing"
	"time"
)

func sample() flow.Window {
	return flow.Window{SchemaVersion: "network.flow/v1alpha1", WindowStart: time.UnixMilli(1700000000000), WindowEnd: time.UnixMilli(1700000001000), Flow: flow.FlowKey{NodeName: "node-a", Protocol: "tcp", Direction: "ingress", Source: flow.Endpoint{Address: "10.0.0.1", Port: 12345}, Destination: flow.Endpoint{Address: "10.0.0.2", Port: 443}}, RTT: flow.Distribution{Count: 2, SumMicros: 30, MinMicros: 10, MaxMicros: 20}, Process: &flow.Process{PID: 42, Cmdline: "private-secret", ContainerID: "observer-container"}, SourceResolved: &flow.ResolvedEndpoint{Address: "10.1.0.1", Port: 2345, Via: "conntrack"}, DestinationResolved: &flow.ResolvedEndpoint{Address: "10.1.0.2", Port: 8443, Via: "conntrack"}}
}
func encoded(m *value.MapValue) []byte {
	return value.WriteValue(xio.NewDataOutputX(), m).ToByteArray()
}
func frame(b []byte) []byte {
	h := make([]byte, 6)
	binary.BigEndian.PutUint16(h, 0xcafe)
	binary.BigEndian.PutUint32(h[2:], uint32(len(b)))
	return append(h, b...)
}
func TestRoundTrip(t *testing.T) {
	w := sample()
	m, err := RequestForWindow(w)
	if err != nil {
		t.Fatal(err)
	}
	if m.GetString("observer_role") != "destination" || m.GetString("observer_container_id") != "observer-container" || m.GetLong("window_start_ms") != w.WindowStart.UnixMilli() || m.GetString("src_addr") != "10.0.0.1" || m.GetString("dst_resolved_addr") != "10.1.0.2" {
		t.Fatal(m)
	}
	for _, k := range []string{"pid", "cmdline", "category", "pcode", "oid", "license"} {
		if m.ContainsKey(k) {
			t.Fatal(k)
		}
	}
	w.Process.Cmdline = "different"
	other, err := RequestForWindow(w)
	if err != nil || other.GetString("request_id") != m.GetString("request_id") {
		t.Fatal("unstable private hash", err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan error, 1)
	go func() {
		c, e := l.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		h := make([]byte, 6)
		_, e = io.ReadFull(c, h)
		if e != nil {
			done <- e
			return
		}
		b := make([]byte, binary.BigEndian.Uint32(h[2:]))
		_, e = io.ReadFull(c, b)
		if e != nil {
			done <- e
			return
		}
		req := value.ReadMapValue(xio.NewDataInputX(b))
		ack := value.NewMapValue()
		ack.PutString("request_id", req.GetString("request_id"))
		ack.Put("ok", value.NewBoolValue(true))
		ack.PutString("stage", "node_queue")
		ack.PutLong("now", 1700000000001)
		_, e = c.Write(frame(encoded(ack)))
		done <- e
	}()
	client, err := NewClient(l.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Send(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}
