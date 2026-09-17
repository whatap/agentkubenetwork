package whatap

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	whatapio "github.com/whatap/golib/io"
	"github.com/whatap/golib/util/hash"
)

func TestRejectMalformedHandshake(t *testing.T) {
	cases := map[string]func([]byte) []byte{
		"source": func(b []byte) []byte { b[0] = 99; return b[:22] },
		"code":   func(b []byte) []byte { b[1] = 0x02; return b[:22] },
		"pcode":  func(b []byte) []byte { b[9] ^= 1; return b[:22] },
		"oid":    func(b []byte) []byte { b[13] ^= 1; return b[:22] },
		"header transfer mismatch": func(b []byte) []byte {
			binary.BigEndian.PutUint32(b[14:18], uint32(testTransfer+1))
			return b
		},
		"truncated header": func(b []byte) []byte { return b[:21] },
		"truncated body":   func(b []byte) []byte { return b[:len(b)-1] },
		"missing body":     func(b []byte) []byte { return b[:22] },
		"negative length": func(b []byte) []byte {
			binary.BigEndian.PutUint32(b[18:22], ^uint32(0))
			return b[:22]
		},
		"oversized length": func(b []byte) []byte {
			binary.BigEndian.PutUint32(b[18:22], 1025)
			return b[:22]
		},
		"huge length": func(b []byte) []byte {
			binary.BigEndian.PutUint32(b[18:22], 0x7fffffff)
			return b[:22]
		},
		"zero length": func(b []byte) []byte {
			binary.BigEndian.PutUint32(b[18:22], 0)
			return b[:22]
		},
		"unaligned length": func(b []byte) []byte {
			binary.BigEndian.PutUint32(b[18:22], 17)
			return b[:22]
		},
		"server error": func(b []byte) []byte {
			b[1] = 0
			message := []byte("SYNTHETIC_COLLECTOR_ERROR_DO_NOT_ECHO")
			binary.BigEndian.PutUint32(b[18:22], uint32(len(message)))
			return b[:22]
		},
	}
	badPlain := map[string][]byte{
		"zero transfer":       whatapio.NewDataOutputX().WriteInt(0).WriteBlob([]byte(testSessionKey)).WriteLong(0).ToByteArray(),
		"empty key":           whatapio.NewDataOutputX().WriteInt(testTransfer).WriteBlob(nil).WriteLong(0).ToByteArray(),
		"short session key":   whatapio.NewDataOutputX().WriteInt(testTransfer).WriteBlob(make([]byte, 15)).WriteLong(0).ToByteArray(),
		"long session key":    whatapio.NewDataOutputX().WriteInt(testTransfer).WriteBlob(make([]byte, 17)).WriteLong(0).ToByteArray(),
		"oversized key":       {0, 0, 0, 1, 254, 127, 255, 255, 255},
		"negative key length": {0, 0, 0, 1, 254, 255, 255, 255, 255},
		"truncated key":       {0, 0, 0, 1, 16, 1},
		"nonzero padding":     append(collectorKeyPlain(), 1),
		"excess padding":      append(collectorKeyPlain(), make([]byte, 16)...),
		"truncated tail":      append([]byte{0, 0, 0, 1, 254, 0, 0, 0, 16}, []byte(testSessionKey)...),
	}
	for name, plain := range badPlain {
		cases[name] = func(b []byte) []byte {
			body := collectorEncrypt([]byte(testMasterKey), plain)
			binary.BigEndian.PutUint32(b[18:22], uint32(len(body)))
			return append(b[:22], body...)
		}
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig()
			collector := startCollector(t, func(conn net.Conn) error {
				if err := collectorHello(conn, cfg); err != nil {
					return err
				}
				base := collectorFrame(3, 0xff, testPcode, hash.HashStr(cfg.ObjectName), 0,
					collectorEncrypt([]byte(testMasterKey), collectorKeyPlain()))
				reply := change(base)
				if _, err := conn.Write(reply); err != nil {
					return err
				}
				// Withhold bodies for invalid headers: reject them without
				// waiting for EOF, allocating, or reading the declared body.
				if len(reply) != 22 || name == "missing body" {
					if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
						return err
					}
				}
				return collectorEOF(conn)
			})
			clientCfg := cfg
			clientCfg.Servers = []string{collector.address()}
			c := testClient(t, clientCfg)
			err := c.Send(context.Background(), testPack(1))
			if err == nil || errors.Is(err, ErrAmbiguousDelivery) {
				t.Fatalf("malformed handshake must fail before data write: %v", err)
			}
			if errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("malformed handshake was not rejected before its deadline")
			}
			if strings.Contains(err.Error(), cfg.AccessKey) || strings.Contains(err.Error(), "SYNTHETIC_COLLECTOR_ERROR_DO_NOT_ECHO") {
				t.Fatal("handshake error leaked credentials or remote error contents")
			}
			collector.wait(t)
		})
	}
}

func TestFailoverBeforeDataWrite(t *testing.T) {
	cfg := testConfig()
	bad := startCollector(t, func(conn net.Conn) error {
		if err := collectorHello(conn, cfg); err != nil {
			return err
		}
		_, err := conn.Write(collectorFrame(3, 0, testPcode, hash.HashStr(cfg.ObjectName), 0, []byte("synthetic rejection"))[:22])
		if err != nil {
			return err
		}
		return collectorEOF(conn)
	})
	good := startCollector(t, func(conn net.Conn) error {
		if err := collectorAuthenticate(conn, cfg); err != nil {
			return err
		}
		p, err := collectorPack(conn, cfg)
		if err == nil && p.Time != 12345 {
			return fmt.Errorf("failover changed the window time")
		}
		return err
	})
	clientCfg := cfg
	clientCfg.Servers = []string{"127.0.0.1:1", bad.address(), good.address()}
	c := testClient(t, clientCfg)
	dial := c.dialContext
	var dials atomic.Int32
	c.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		if address == "127.0.0.1:1" {
			return nil, errors.New("synthetic connection refusal")
		}
		return dial(ctx, network, address)
	}
	if err := c.Send(context.Background(), testPack(12345)); err != nil {
		t.Fatal(err)
	}
	if dials.Load() != 3 {
		t.Fatalf("expected one finite attempt per server, got %d", dials.Load())
	}
	bad.wait(t)
	good.wait(t)
}

func TestFailoverSharesTotalTimeout(t *testing.T) {
	cfg := testConfig()
	slow := startCollector(t, func(conn net.Conn) error {
		if err := collectorHello(conn, cfg); err != nil {
			return err
		}
		return collectorEOF(conn) // Withhold key reply until the attempt expires.
	})
	good := startCollector(t, func(conn net.Conn) error {
		if err := collectorAuthenticate(conn, cfg); err != nil {
			return err
		}
		_, err := collectorPack(conn, cfg)
		return err
	})
	clientCfg := cfg
	clientCfg.Servers = []string{slow.address(), good.address()}
	clientCfg.Timeout = 400 * time.Millisecond
	c := testClient(t, clientCfg)
	start := time.Now()
	if err := c.Send(context.Background(), testPack(1)); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > clientCfg.Timeout+200*time.Millisecond {
		t.Fatalf("timeout was restarted per server: %v", elapsed)
	}
	slow.wait(t)
	good.wait(t)
}

func TestFailoverStopsAfterConfiguredServers(t *testing.T) {
	cfg := testConfig()
	cfg.Servers = []string{"127.0.0.1:1", "127.0.0.1:2"}
	c := testClient(t, cfg)
	var dials atomic.Int32
	refused := errors.New("synthetic connection refusal")
	c.dialContext = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, refused
	}
	if err := c.Send(context.Background(), testPack(1)); !errors.Is(err, refused) || errors.Is(err, ErrAmbiguousDelivery) {
		t.Fatalf("connection refusal: %v", err)
	}
	if dials.Load() != 2 || c.currentSession() != nil {
		t.Fatal("did not stop after configured servers")
	}
}
