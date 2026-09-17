package whatap

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/whatap/golib/util/hash"
)

func hashOID(cfg Config) int32 { return hash.HashStr(cfg.ObjectName) }

func TestReceiverRejectsMalformedFrames(t *testing.T) {
	cases := map[string]func([]byte) []byte{
		"source":          func(b []byte) []byte { b[0] = 99; return b[:22] },
		"pcode":           func(b []byte) []byte { b[9] ^= 1; return b[:22] },
		"oid":             func(b []byte) []byte { b[13] ^= 1; return b[:22] },
		"transfer":        func(b []byte) []byte { b[17] ^= 1; return b[:22] },
		"plaintext":       func(b []byte) []byte { b[1] = 4; return b[:22] },
		"unsolicited key": func(b []byte) []byte { b[1] = 0xff; return b[:22] },
		"bad clock":       func(b []byte) []byte { b[1] = 0xfe; return b[:22] },
		"negative size": func(b []byte) []byte {
			binary.BigEndian.PutUint32(b[18:22], ^uint32(0))
			return b[:22]
		},
		"oversized size": func(b []byte) []byte {
			binary.BigEndian.PutUint32(b[18:22], 8*1024*1024+1)
			return b[:22]
		},
		"zero size": func(b []byte) []byte {
			binary.BigEndian.PutUint32(b[18:22], 0)
			return b[:22]
		},
		"unaligned cipher": func(b []byte) []byte {
			binary.BigEndian.PutUint32(b[18:22], 17)
			return b[:22]
		},
		"truncated header": func(b []byte) []byte { return b[:21] },
		"truncated body":   func(b []byte) []byte { return b[:len(b)-1] },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig()
			release := make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			collector := startCollector(t, func(conn net.Conn) error {
				if err := collectorAuthenticate(conn, cfg); err != nil {
					return err
				}
				if _, err := collectorPack(conn, cfg); err != nil {
					return err
				}
				<-release
				frame := change(collectorFrame(3, 0x02, testPcode, hashOID(cfg), testTransfer, make([]byte, 32)))
				if _, err := conn.Write(frame); err != nil {
					return err
				}
				if len(frame) != 22 {
					if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
						return err
					}
				}
				return collectorEOF(conn)
			})
			clientCfg := cfg
			clientCfg.Servers = []string{collector.address()}
			c := testClient(t, clientCfg)
			var dials atomic.Int32
			dial := c.dialContext
			c.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				dials.Add(1)
				return dial(ctx, network, address)
			}
			if err := c.Send(context.Background(), testPack(1)); err != nil {
				t.Fatal(err)
			}
			s := c.currentSession()
			if s == nil {
				t.Fatal("connection closed before malformed frame")
			}
			once.Do(func() { close(release) })
			awaitSignal(t, s.closed)
			_ = c.Close()
			if dials.Load() != 1 {
				t.Fatal("receiver started a background reconnect")
			}
			collector.wait(t)
		})
	}
}

func TestReceiverTimesOutIncompleteFrames(t *testing.T) {
	for _, bodyStarted := range []bool{false, true} {
		t.Run(fmt.Sprint(bodyStarted), func(t *testing.T) {
			cfg := testConfig()
			release := make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			collector := startCollector(t, func(conn net.Conn) error {
				if err := collectorAuthenticate(conn, cfg); err != nil {
					return err
				}
				if _, err := collectorPack(conn, cfg); err != nil {
					return err
				}
				<-release
				frame := collectorFrame(3, 0x02, testPcode, hashOID(cfg), testTransfer, make([]byte, 32))
				size := 1
				if bodyStarted {
					size = 23
				}
				if _, err := conn.Write(frame[:size]); err != nil {
					return err
				}
				return collectorEOF(conn)
			})
			clientCfg := cfg
			clientCfg.Servers = []string{collector.address()}
			clientCfg.Timeout = 100 * time.Millisecond
			c := testClient(t, clientCfg)
			if err := c.Send(context.Background(), testPack(1)); err != nil {
				t.Fatal(err)
			}
			s := c.currentSession()
			if s == nil {
				t.Fatal("connection was not established")
			}
			once.Do(func() { close(release) })
			awaitSignal(t, s.closed)
			collector.wait(t)
		})
	}
}

func TestReceiverDiscardsFramesAndCloseStopsIdleRead(t *testing.T) {
	cfg := testConfig()
	incoming := append(collectorFrame(3, 0x01, testPcode, hashOID(cfg), testTransfer, make([]byte, 128*1024)),
		collectorFrame(4, 0x02, testPcode, hashOID(cfg), testTransfer, make([]byte, 256*1024))...)
	incoming = append(incoming, collectorFrame(3, 0xfe, testPcode, hashOID(cfg), 0, make([]byte, 16))...)
	collector := startCollector(t, func(conn net.Conn) error {
		if err := collectorAuthenticate(conn, cfg); err != nil {
			return err
		}
		if _, err := collectorPack(conn, cfg); err != nil {
			return err
		}
		if _, err := conn.Write(incoming); err != nil {
			return err
		}
		p, err := collectorPack(conn, cfg)
		if err != nil || p.Time != 12345 {
			return fmt.Errorf("receiver changed the connection or window: %v", err)
		}
		return collectorEOF(conn)
	})
	clientCfg := cfg
	clientCfg.Servers = []string{collector.address()}
	c := testClient(t, clientCfg)
	drained := make(chan struct{})
	var readBytes atomic.Int64
	var once sync.Once
	dial := c.dialContext
	c.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &controlledConn{Conn: conn, read: func(b []byte) (int, error) {
			n, err := conn.Read(b)
			if readBytes.Add(int64(n)) >= int64(22+32+len(incoming)) {
				once.Do(func() { close(drained) })
			}
			return n, err
		}}, nil
	}
	if err := c.Send(context.Background(), testPack(1)); err != nil {
		t.Fatal(err)
	}
	awaitSignal(t, drained)
	if err := c.Send(context.Background(), testPack(12345)); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	collector.wait(t)
}

func TestIdleConnectionSurvivesBetweenWindows(t *testing.T) {
	cfg := testConfig()
	collector := startCollector(t, func(conn net.Conn) error {
		if err := collectorAuthenticate(conn, cfg); err != nil {
			return err
		}
		for i := 0; i < 2; i++ {
			if _, err := collectorPack(conn, cfg); err != nil {
				return err
			}
		}
		return nil
	})
	clientCfg := cfg
	clientCfg.Servers = []string{collector.address()}
	clientCfg.Timeout = 100 * time.Millisecond
	c := testClient(t, clientCfg)
	if err := c.Send(context.Background(), testPack(1)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(220 * time.Millisecond)
	if err := c.Send(context.Background(), testPack(2)); err != nil {
		t.Fatalf("idle connection was not reusable: %v", err)
	}
	collector.wait(t)
}
