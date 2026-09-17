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

	"github.com/whatap/golib/util/hash"
)

func awaitSignal(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("operation did not reach the expected I/O stage")
	}
}

func awaitSend(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("Send did not stop")
		return nil
	}
}

func TestCanceledContextDoesNotDial(t *testing.T) {
	c := testClient(t, testConfig())
	var dials atomic.Int32
	c.dialContext = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("unexpected dial")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Send(ctx, testPack(1)); !errors.Is(err, context.Canceled) || errors.Is(err, ErrAmbiguousDelivery) {
		t.Fatalf("pre-canceled Send: %v", err)
	}
	if dials.Load() != 0 {
		t.Fatal("canceled context started dialing")
	}
}

func TestCancelCloseAndTimeoutDuringDial(t *testing.T) {
	for _, action := range []string{"cancel", "close", "timeout"} {
		t.Run(action, func(t *testing.T) {
			cfg := testConfig()
			if action == "timeout" {
				cfg.Timeout = 80 * time.Millisecond
			}
			c := testClient(t, cfg)
			started := make(chan struct{})
			c.dialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
				close(started)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- c.Send(ctx, testPack(1)) }()
			awaitSignal(t, started)
			want := error(context.DeadlineExceeded)
			if action == "cancel" {
				cancel()
				want = context.Canceled
			} else if action == "close" {
				_ = c.Close()
				want = ErrClosed
			}
			if err := awaitSend(t, result); !errors.Is(err, want) || errors.Is(err, ErrAmbiguousDelivery) {
				t.Fatalf("interrupted dial: %v; want %v", err, want)
			}
		})
	}
}

func TestCloseRejectsConnectionReturnedAfterDial(t *testing.T) {
	c := testClient(t, testConfig())
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	c.dialContext = func(context.Context, string, string) (net.Conn, error) {
		close(started)
		<-release
		return conn, nil // Simulate the dial-completion/Close race.
	}
	result := make(chan error, 1)
	go func() { result <- c.Send(context.Background(), testPack(1)) }()
	awaitSignal(t, started)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	releaseOnce.Do(func() { close(release) })
	if err := awaitSend(t, result); !errors.Is(err, ErrClosed) {
		t.Fatalf("late dial result: %v", err)
	}
	if err := collectorEOF(peer); err != nil {
		t.Fatal(err)
	}
}

func TestCancelCloseAndTimeoutDuringHandshake(t *testing.T) {
	for _, action := range []string{"cancel", "close", "timeout", "context deadline"} {
		t.Run(action, func(t *testing.T) {
			cfg := testConfig()
			started := make(chan struct{})
			collector := startCollector(t, func(conn net.Conn) error {
				if err := collectorHello(conn, cfg); err != nil {
					return err
				}
				close(started)
				return collectorEOF(conn)
			})
			clientCfg := cfg
			clientCfg.Servers = []string{collector.address()}
			if action == "timeout" {
				clientCfg.Timeout = 80 * time.Millisecond
			}
			c := testClient(t, clientCfg)
			ctx, cancel := context.WithCancel(context.Background())
			if action == "context deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 80*time.Millisecond)
			}
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- c.Send(ctx, testPack(1)) }()
			awaitSignal(t, started)
			want := error(context.DeadlineExceeded)
			if action == "cancel" {
				cancel()
				want = context.Canceled
			} else if action == "close" {
				_ = c.Close()
				want = ErrClosed
			}
			if err := awaitSend(t, result); !errors.Is(err, want) || errors.Is(err, ErrAmbiguousDelivery) {
				t.Fatalf("interrupted handshake: %v; want %v", err, want)
			}
			collector.wait(t)
		})
	}
}

func TestWaitingSendCancellationDoesNotInterruptActiveSend(t *testing.T) {
	cfg := testConfig()
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	collector := startCollector(t, func(conn net.Conn) error {
		if err := collectorHello(conn, cfg); err != nil {
			return err
		}
		close(started)
		<-release
		reply := collectorFrame(3, 0xff, testPcode, hash.HashStr(cfg.ObjectName), 0,
			collectorEncrypt([]byte(testMasterKey), collectorKeyPlain()))
		if _, err := conn.Write(reply); err != nil {
			return err
		}
		p, err := collectorPack(conn, cfg)
		if err == nil && p.Time != 1 {
			return fmt.Errorf("canceled waiter was written")
		}
		return err
	})
	clientCfg := cfg
	clientCfg.Servers = []string{collector.address()}
	c := testClient(t, clientCfg)
	result := make(chan error, 1)
	go func() { result <- c.Send(context.Background(), testPack(1)) }()
	awaitSignal(t, started)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	if err := c.Send(ctx, testPack(2)); !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrAmbiguousDelivery) {
		t.Fatalf("waiting Send: %v", err)
	}
	if s := c.currentSession(); s == nil || s.isClosed() {
		t.Fatal("canceling a waiter closed the active connection")
	}
	releaseOnce.Do(func() { close(release) })
	if err := awaitSend(t, result); err != nil {
		t.Fatal(err)
	}
	collector.wait(t)
}

func TestConcurrentCloseInterruptsSendAndWaiters(t *testing.T) {
	cfg := testConfig()
	started := make(chan struct{})
	collector := startCollector(t, func(conn net.Conn) error {
		if err := collectorHello(conn, cfg); err != nil {
			return err
		}
		close(started)
		return collectorEOF(conn)
	})
	clientCfg := cfg
	clientCfg.Servers = []string{collector.address()}
	c := testClient(t, clientCfg)
	const count = 24
	results := make(chan error, count)
	go func() { results <- c.Send(context.Background(), testPack(1)) }()
	awaitSignal(t, started)
	for i := 1; i < count; i++ {
		go func() { results <- c.Send(context.Background(), testPack(2)) }()
	}
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Identity()
			if err := c.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	for i := 0; i < count; i++ {
		if err := awaitSend(t, results); !errors.Is(err, ErrClosed) || errors.Is(err, ErrAmbiguousDelivery) {
			t.Fatalf("Send during terminal Close: %v", err)
		}
	}
	collector.wait(t)
}

// These wrappers keep real TCP I/O while injecting otherwise nondeterministic
// short writes, deadline failures, and cancellation during a partial write.
type controlledConn struct {
	net.Conn
	write         func([]byte) (int, error)
	read          func([]byte) (int, error)
	close         func() error
	writeDeadline func(time.Time) error
}

func (c *controlledConn) Write(b []byte) (int, error) {
	if c.write != nil {
		return c.write(b)
	}
	return c.Conn.Write(b)
}

func (c *controlledConn) Read(b []byte) (int, error) {
	if c.read != nil {
		return c.read(b)
	}
	return c.Conn.Read(b)
}

func (c *controlledConn) Close() error {
	if c.close != nil {
		return c.close()
	}
	return c.Conn.Close()
}

func (c *controlledConn) SetWriteDeadline(deadline time.Time) error {
	if c.writeDeadline != nil {
		return c.writeDeadline(deadline)
	}
	return c.Conn.SetWriteDeadline(deadline)
}

func TestCancelCloseAndTimeoutDuringPartialWrite(t *testing.T) {
	for _, action := range []string{"cancel", "close", "timeout"} {
		t.Run(action, func(t *testing.T) {
			cfg := testConfig()
			collector := startCollector(t, func(conn net.Conn) error {
				if err := collectorAuthenticate(conn, cfg); err != nil {
					return err
				}
				data, err := io.ReadAll(conn)
				if err != nil || len(data) != 7 || data[0] != 1 || data[1] != 0x02 {
					return fmt.Errorf("partial frame: size=%d err=%v", len(data), err)
				}
				return nil
			})
			clientCfg := cfg
			clientCfg.Servers = []string{collector.address(), "127.0.0.1:1"}
			if action == "timeout" {
				clientCfg.Timeout = 160 * time.Millisecond
			}
			c := testClient(t, clientCfg)
			started, closed := make(chan struct{}), make(chan struct{})
			dial := c.dialContext
			var dials atomic.Int32
			c.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				if dials.Add(1) != 1 {
					return nil, errors.New("forbidden retry after data write")
				}
				conn, err := dial(ctx, network, address)
				if err != nil {
					return nil, err
				}
				writes := 0
				var once sync.Once
				return &controlledConn{
					Conn: conn,
					write: func(b []byte) (int, error) {
						writes++
						if writes == 1 {
							return conn.Write(b)
						}
						n, err := conn.Write(b[:7])
						if err != nil {
							return n, err
						}
						close(started)
						<-closed
						return n, net.ErrClosed
					},
					close: func() error {
						once.Do(func() { close(closed) })
						return conn.Close()
					},
				}, nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- c.Send(ctx, testPack(1)) }()
			awaitSignal(t, started)
			want := error(context.DeadlineExceeded)
			if action == "cancel" {
				cancel()
				want = context.Canceled
			} else if action == "close" {
				_ = c.Close()
				want = ErrClosed
			}
			if err := awaitSend(t, result); !errors.Is(err, ErrAmbiguousDelivery) || !errors.Is(err, want) {
				t.Fatalf("partial write interruption: %v; want ambiguous and %v", err, want)
			}
			if dials.Load() != 1 {
				t.Fatal("automatically retried a partially written pack")
			}
			collector.wait(t)
		})
	}
}

func TestShortReadsAndWritesOnRealTCP(t *testing.T) {
	cfg := testConfig()
	collector := startCollector(t, func(conn net.Conn) error {
		if err := collectorAuthenticate(conn, cfg); err != nil {
			return err
		}
		for i := 0; i < 2; i++ {
			p, err := collectorPack(conn, cfg)
			if err != nil || p.Time != int64(i) {
				return fmt.Errorf("fragmented window %d: %v", i, err)
			}
		}
		return nil
	})
	clientCfg := cfg
	clientCfg.Servers = []string{collector.address()}
	c := testClient(t, clientCfg)
	dial := c.dialContext
	c.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &controlledConn{
			Conn: conn,
			write: func(b []byte) (int, error) {
				if len(b) > 3 {
					b = b[:3]
				}
				return conn.Write(b)
			},
			read: func(b []byte) (int, error) {
				if len(b) > 2 {
					b = b[:2]
				}
				return conn.Read(b)
			},
		}, nil
	}
	for i := 0; i < 2; i++ {
		if err := c.Send(context.Background(), testPack(int64(i))); err != nil {
			t.Fatal(err)
		}
	}
	collector.wait(t)
}
