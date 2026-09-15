package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	xio "github.com/whatap/golib/io"
	"github.com/whatap/golib/lang/value"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

const windowJSON = `{"schemaVersion":"network.flow/v1alpha1","windowStart":"2023-11-14T22:13:20Z","windowEnd":"2023-11-14T22:13:21Z","flow":{"nodeName":"node-a","protocol":"tcp","direction":"egress","source":{"address":"10.0.0.1","port":12345},"destination":{"address":"10.0.0.2","port":443}},"rtt":{"count":2,"sumMicros":30,"minMicros":10,"maxMicros":20}}`

func TestCLITransport(t *testing.T) {
	for _, accept := range []bool{true, false} {
		t.Run(fmt.Sprint(accept), func(t *testing.T) {
			l, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
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
				if _, e = io.ReadFull(c, h); e != nil {
					done <- e
					return
				}
				n := binary.BigEndian.Uint32(h[2:])
				if n > 65536 {
					done <- fmt.Errorf("too large")
					return
				}
				b := make([]byte, int(n))
				if _, e = io.ReadFull(c, b); e != nil {
					done <- e
					return
				}
				m := value.ReadMapValue(xio.NewDataInputX(b))
				a := value.NewMapValue()
				a.PutString("request_id", m.GetString("request_id"))
				a.Put("ok", value.NewBoolValue(accept))
				a.PutString("stage", "node_queue")
				a.PutLong("now", 1700000000001)
				if !accept {
					a.PutString("code", "QUEUE_FULL")
				}
				b = value.WriteValue(xio.NewDataOutputX(), a).ToByteArray()
				binary.BigEndian.PutUint16(h, 0xcafe)
				binary.BigEndian.PutUint32(h[2:], uint32(len(b)))
				_, e = c.Write(append(h, b...))
				done <- e
			}()
			var out, errs bytes.Buffer
			code := run([]string{"-address", l.Addr().String()}, strings.NewReader(windowJSON+"\n"), &out, &errs)
			if accept && (code != 0 || !strings.Contains(out.String(), `"accepted":1`)) {
				t.Fatal(code, out.String(), errs.String())
			}
			if !accept && code == 0 {
				t.Fatal("rejection succeeded")
			}
			if !accept && (!strings.Contains(out.String(), `"accepted":0`) || !strings.Contains(out.String(), `"failed":1`)) {
				t.Fatalf("terminal counts lost after rejection: %q", out.String())
			}
			if e = <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestRejectInvalidUTF8AndFractionalSamples(t *testing.T) {
	for _, s := range []string{`{"schemaVersion":"other","value":"` + string([]byte{255}) + `"}`, strings.Replace(windowJSON, `"sumMicros":30`, `"sumMicros":30.5`, 1), strings.Repeat("x", 1024*1024+1)} {
		var out, errs bytes.Buffer
		if run([]string{"-address", "127.0.0.1:12345"}, strings.NewReader(s), &out, &errs) == 0 {
			t.Fatal("accepted invalid input")
		}
	}
}
