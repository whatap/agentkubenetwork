package bridge

import (
	"bytes"
	"context"
	"errors"
	"github.com/whatap/agentkubenetwork/internal/flow"
	"github.com/whatap/golib/lang/value"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestValidation(t *testing.T) {
	cases := map[string]func(*flow.Window){"schema": func(w *flow.Window) { w.SchemaVersion = "network.window/v1" }, "start": func(w *flow.Window) { w.WindowStart = time.UnixMilli(0) }, "interval": func(w *flow.Window) { w.WindowEnd = w.WindowStart.Add(61 * time.Second) }, "node": func(w *flow.Window) { w.Flow.NodeName = "bad node" }, "protocol": func(w *flow.Window) { w.Flow.Protocol = "udp" }, "unspecified": func(w *flow.Window) { w.Flow.Source.Address = "0.0.0.0" }, "multicast": func(w *flow.Window) { w.Flow.Source.Address = "224.0.0.1" }, "hostname": func(w *flow.Window) { w.Flow.Source.Address = "localhost" }, "zone": func(w *flow.Window) { w.Flow.Source.Address = "fe80::1%en0" }, "port": func(w *flow.Window) { w.Flow.Source.Port = 0 }, "count": func(w *flow.Window) { w.RTT.Count = 1000000001 }, "overflow": func(w *flow.Window) { w.RTT.SumMicros = 1 << 63 }, "sum": func(w *flow.Window) { w.RTT.SumMicros = 31 }, "extrema": func(w *flow.Window) { w.RTT.Count = 1 }, "zero": func(w *flow.Window) { w.RTT.MinMicros = 0 }, "container": func(w *flow.Window) { w.Process.ContainerID = "bad id" }, "resolution": func(w *flow.Window) { w.SourceResolved.Via = "bad via" }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			w := sample()
			change(&w)
			if _, e := RequestForWindow(w); e == nil {
				t.Fatal("accepted invalid record")
			}
		})
	}
	w := sample()
	w.Partial = true
	if _, e := RequestForWindow(w); !errors.Is(e, ErrPartialWindow) {
		t.Fatal(e)
	}
	w.Partial = false
	w.RTT.Count = 0
	if _, e := RequestForWindow(w); !errors.Is(e, ErrNoSamples) {
		t.Fatal(e)
	}
	for _, a := range []string{"localhost:1234", "0.0.0.0:1234", "192.0.2.1:1234", "127.0.0.1:0", "127.0.0.1:65536", "[::1%en0]:1234"} {
		if _, e := NewClient(a, time.Second); e == nil {
			t.Fatal(a)
		}
	}
	if _, e := NewClient("127.0.0.1:1234", 0); e == nil {
		t.Fatal("timeout")
	}
}
func validAck() *value.MapValue {
	m := value.NewMapValue()
	m.PutString("request_id", "request")
	m.Put("ok", value.NewBoolValue(true))
	m.PutString("stage", "node_queue")
	m.PutLong("now", 1700000000000)
	return m
}
func TestSafePreflight(t *testing.T) {
	good := encoded(validAck())
	if e := preflightMap(good); e != nil {
		t.Fatal(e)
	}
	bad := [][]byte{nil, {80, 1, 33}, {80, 1, 1, 254, 127, 255, 255, 255}, {80, 1, 1, 1, 'x', 50, 254, 127, 255, 255, 255}, {80, 1, 1, 1, 'x', 80, 0}, {80, 1, 1, 1, 'x', 10, 2}, {80, 1, 1, 1, 255, 10, 1}, {80, 1, 2, 1, 'x', 10, 1, 1, 'x', 10, 1}, append(append([]byte{}, good...), 0)}
	for i := 0; i < len(good); i++ {
		bad = append(bad, good[:i])
	}
	for i, b := range bad {
		if e := preflightMap(b); e == nil {
			t.Fatalf("accepted bad body %d", i)
		}
	}
	m := validAck()
	m.PutString("extra", strings.Repeat("x", 513))
	if e := preflightMap(encoded(m)); e == nil {
		t.Fatal("oversized inner text")
	}
}
func TestExactACK(t *testing.T) {
	cases := map[string]func(*value.MapValue){"id": func(m *value.MapValue) { m.PutString("request_id", "wrong") }, "stage": func(m *value.MapValue) { m.PutString("stage", "backend") }, "extra": func(m *value.MapValue) { m.PutLong("extra", 1) }, "type": func(m *value.MapValue) { m.PutString("ok", "true") }, "now": func(m *value.MapValue) { m.PutLong("now", 0) }, "code": func(m *value.MapValue) { m.PutString("code", "INTERNAL") }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			m := validAck()
			change(m)
			if _, e := readAck(bytes.NewReader(frame(encoded(m))), "request"); e == nil {
				t.Fatal("accepted invalid ACK")
			}
		})
	}
	m := validAck()
	m.Put("ok", value.NewBoolValue(false))
	m.PutString("code", "QUEUE_FULL")
	if _, e := readAck(bytes.NewReader(frame(encoded(m))), "request"); !errors.Is(e, ErrRejected) {
		t.Fatal(e)
	}
	for _, b := range [][]byte{{0xca, 0xfe, 0xff, 0xff, 0xff, 0xff}, {0xca, 0xfe, 0, 0, 16, 1}, {0, 0, 0, 0, 0, 1}} {
		if _, e := readAck(bytes.NewReader(b), "request"); e == nil {
			t.Fatal("bad header")
		}
	}
}
func TestAmbiguityAndCancellationNoRetry(t *testing.T) {
	for _, mode := range []string{"close", "deadline", "cancel", "mismatch", "reject"} {
		t.Run(mode, func(t *testing.T) {
			l, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			var count atomic.Int32
			received := make(chan struct{})
			done := make(chan struct{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				defer close(done)
				c, e := l.Accept()
				if e != nil {
					return
				}
				count.Add(1)
				defer c.Close()
				c.SetDeadline(time.Now().Add(time.Second))
				h := make([]byte, 6)
				if _, e = io.ReadFull(c, h); e != nil {
					return
				}
				b := make([]byte, int(h[4])<<8|int(h[5]))
				if _, e = io.ReadFull(c, b); e != nil {
					return
				}
				close(received)
				switch mode {
				case "deadline":
					time.Sleep(80 * time.Millisecond)
				case "cancel":
					<-ctx.Done()
				case "mismatch":
					c.Write(frame(encoded(validAck())))
				case "reject":
					m, _ := RequestForWindow(sample())
					a := validAck()
					a.PutString("request_id", m.GetString("request_id"))
					a.Put("ok", value.NewBoolValue(false))
					a.PutString("code", "QUEUE_FULL")
					c.Write(frame(encoded(a)))
				}
			}()
			if mode == "cancel" {
				go func() { <-received; cancel() }()
			}
			c, _ := NewClient(l.Addr().String(), 40*time.Millisecond)
			e = c.Send(ctx, sample())
			want := ErrAmbiguousDelivery
			if mode == "reject" {
				want = ErrRejected
			}
			if !errors.Is(e, want) {
				t.Fatalf("%v want %v", e, want)
			}
			<-done
			if count.Load() != 1 {
				t.Fatal("retry")
			}
			l.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Millisecond))
			if extra, e := l.Accept(); e == nil {
				extra.Close()
				t.Fatal("retried connection")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c, _ := NewClient("127.0.0.1:12345", time.Second)
	if e := c.Send(ctx, sample()); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
