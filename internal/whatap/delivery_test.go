package whatap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAmbiguousWriteNeverRetries(t *testing.T) {
	for _, mode := range []string{"zero error", "partial error", "complete error", "zero progress", "cancel after complete"} {
		t.Run(mode, func(t *testing.T) {
			cfg := testConfig()
			collector := startCollector(t, func(conn net.Conn) error {
				if err := collectorAuthenticate(conn, cfg); err != nil {
					return err
				}
				if mode == "complete error" || mode == "cancel after complete" {
					p, err := collectorPack(conn, cfg)
					if err != nil || p.Time != 12345 {
						return fmt.Errorf("complete but ambiguous delivery: %v", err)
					}
					return collectorEOF(conn)
				}
				data, err := io.ReadAll(conn)
				want := 0
				if mode == "partial error" {
					want = 7
				}
				if err != nil || len(data) != want {
					return fmt.Errorf("unexpected data after failure: size=%d want=%d err=%v", len(data), want, err)
				}
				return nil
			})
			clientCfg := cfg
			clientCfg.Servers = []string{collector.address(), "127.0.0.1:1"}
			c := testClient(t, clientCfg)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			failure := errors.New("synthetic write failure")
			dial := c.dialContext
			var dials, dataWrites atomic.Int32
			c.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				if dials.Add(1) != 1 {
					return nil, errors.New("forbidden failover")
				}
				conn, err := dial(ctx, network, address)
				if err != nil {
					return nil, err
				}
				writes := 0
				return &controlledConn{Conn: conn, write: func(b []byte) (int, error) {
					writes++
					if writes == 1 {
						return conn.Write(b)
					}
					dataWrites.Add(1)
					switch mode {
					case "zero error":
						return 0, failure
					case "zero progress":
						return 0, nil
					case "partial error":
						n, err := conn.Write(b[:7])
						if err != nil {
							return n, err
						}
						return n, failure
					default:
						n, err := conn.Write(b)
						if err != nil {
							return n, err
						}
						if mode == "cancel after complete" {
							cancel()
							return n, nil
						}
						return n, failure
					}
				}}, nil
			}
			want := failure
			if mode == "zero progress" {
				want = io.ErrNoProgress
			} else if mode == "cancel after complete" {
				want = context.Canceled
			}
			if err := c.Send(ctx, testPack(12345)); !errors.Is(err, ErrAmbiguousDelivery) || !errors.Is(err, want) {
				t.Fatalf("write result: %v; want ambiguous and %v", err, want)
			}
			if dials.Load() != 1 || dataWrites.Load() != 1 || c.currentSession() != nil {
				t.Fatal("ambiguous delivery was retried or its connection was retained")
			}
			collector.wait(t)
		})
	}
}

func TestDeadlineFailureBeforeDataAllowsFailover(t *testing.T) {
	cfg := testConfig()
	bad := startCollector(t, func(conn net.Conn) error {
		if err := collectorAuthenticate(conn, cfg); err != nil {
			return err
		}
		return collectorEOF(conn)
	})
	good := startCollector(t, func(conn net.Conn) error {
		if err := collectorAuthenticate(conn, cfg); err != nil {
			return err
		}
		_, err := collectorPack(conn, cfg)
		return err
	})
	clientCfg := cfg
	clientCfg.Servers = []string{bad.address(), good.address()}
	c := testClient(t, clientCfg)
	dial := c.dialContext
	var dials atomic.Int32
	c.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		conn, err := dial(ctx, network, address)
		if err != nil || address == good.address() {
			return conn, err
		}
		return &controlledConn{Conn: conn, writeDeadline: func(time.Time) error {
			return errors.New("synthetic pre-write deadline failure")
		}}, nil
	}
	if err := c.Send(context.Background(), testPack(1)); err != nil {
		t.Fatal(err)
	}
	if dials.Load() != 2 {
		t.Fatal("pre-data failover did not reach the second server exactly once")
	}
	bad.wait(t)
	good.wait(t)
}

func TestReusedConnectionFailureRequiresANewSendToReconnect(t *testing.T) {
	cfg := testConfig()
	first := startCollector(t, func(conn net.Conn) error {
		if err := collectorAuthenticate(conn, cfg); err != nil {
			return err
		}
		for _, window := range []int64{0, 1} {
			p, err := collectorPack(conn, cfg)
			if err != nil || p.Time != window {
				return fmt.Errorf("original connection window %d: %v", window, err)
			}
		}
		return collectorEOF(conn)
	})
	second := startCollector(t, func(conn net.Conn) error {
		if err := collectorAuthenticate(conn, cfg); err != nil {
			return err
		}
		p, err := collectorPack(conn, cfg)
		if err != nil || p.Time != 2 {
			return fmt.Errorf("old window retried on next connection: %v", err)
		}
		return nil
	})
	clientCfg := cfg
	clientCfg.Servers = []string{first.address(), second.address()}
	c := testClient(t, clientCfg)
	dial := c.dialContext
	var dials atomic.Int32
	failure := errors.New("synthetic reused-connection write failure")
	c.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		n := dials.Add(1)
		if address == first.address() && n != 1 {
			return nil, errors.New("synthetic refusal on next window")
		}
		conn, err := dial(ctx, network, address)
		if err != nil || address == second.address() {
			return conn, err
		}
		writes := 0
		return &controlledConn{Conn: conn, write: func(b []byte) (int, error) {
			writes++
			n, err := conn.Write(b)
			if err == nil && writes == 3 { // Hello, warm-up pack, then failed pack.
				err = failure
			}
			return n, err
		}}, nil
	}
	if err := c.Send(context.Background(), testPack(0)); err != nil {
		t.Fatal(err)
	}
	if err := c.Send(context.Background(), testPack(1)); !errors.Is(err, ErrAmbiguousDelivery) || !errors.Is(err, failure) {
		t.Fatalf("reused-connection failure: %v", err)
	}
	if dials.Load() != 1 {
		t.Fatal("automatically retried the ambiguous window")
	}
	first.wait(t)
	if err := c.Send(context.Background(), testPack(2)); err != nil {
		t.Fatal(err)
	}
	if dials.Load() != 3 {
		t.Fatal("a new Send did not perform finite reconnection")
	}
	second.wait(t)
}

func TestTotalTimeoutSpansDialHandshakeAndWrite(t *testing.T) {
	cfg := testConfig()
	collector := startCollector(t, func(conn net.Conn) error {
		if err := collectorHello(conn, cfg); err != nil {
			return err
		}
		time.Sleep(100 * time.Millisecond)
		reply := collectorFrame(3, 0xff, testPcode, hashOID(cfg), 0,
			collectorEncrypt([]byte(testMasterKey), collectorKeyPlain()))
		if _, err := conn.Write(reply); err != nil {
			return err
		}
		data, err := io.ReadAll(conn)
		if err != nil || len(data) != 7 {
			return fmt.Errorf("expected a blocked partial write: size=%d err=%v", len(data), err)
		}
		return nil
	})
	clientCfg := cfg
	clientCfg.Servers = []string{collector.address()}
	clientCfg.Timeout = 300 * time.Millisecond
	c := testClient(t, clientCfg)
	dial := c.dialContext
	var deadlineChecked atomic.Bool
	c.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			return nil, errors.New("dial had no deadline")
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		closed := make(chan struct{})
		var once sync.Once
		writes := 0
		return &controlledConn{
			Conn: conn,
			writeDeadline: func(sendDeadline time.Time) error {
				if !sendDeadline.Equal(deadline) {
					return errors.New("deadline was restarted after dial/handshake")
				}
				deadlineChecked.Store(true)
				return conn.SetWriteDeadline(sendDeadline)
			},
			write: func(b []byte) (int, error) {
				writes++
				if writes == 1 {
					return conn.Write(b)
				}
				n, err := conn.Write(b[:7])
				if err != nil {
					return n, err
				}
				<-closed
				return n, net.ErrClosed
			},
			close: func() error {
				once.Do(func() { close(closed) })
				return conn.Close()
			},
		}, nil
	}
	if err := c.Send(context.Background(), testPack(1)); !errors.Is(err, ErrAmbiguousDelivery) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("combined timeout: %v", err)
	}
	if !deadlineChecked.Load() {
		t.Fatal("test did not reach payload I/O using the original deadline")
	}
	collector.wait(t)
}
