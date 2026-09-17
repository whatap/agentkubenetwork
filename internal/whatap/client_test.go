package whatap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/whatap/golib/lang/pack"
	"github.com/whatap/golib/util/hash"
)

func TestNewClientIsLazyAndCopiesServers(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cfg := testConfig()
	cfg.Servers = []string{listener.Addr().String()}
	c := testClient(t, cfg)
	pcode, oid := c.Identity()
	if pcode != testPcode || oid != hash.HashStr(cfg.ObjectName) {
		t.Fatal("identity did not come from license and object name")
	}
	if c.currentSession() != nil {
		t.Fatal("NewClient created a session")
	}
	cfg.Servers[0] = "127.0.0.1:2"
	if c.servers[0] != listener.Addr().String() {
		t.Fatal("client retained caller's server slice")
	}
	_ = listener.SetDeadline(time.Now().Add(30 * time.Millisecond))
	if conn, err := listener.Accept(); err == nil {
		_ = conn.Close()
		t.Fatal("NewClient started network I/O")
	} else if e, ok := err.(net.Error); !ok || !e.Timeout() {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Send(context.Background(), testPack(1)); !errors.Is(err, ErrClosed) {
		t.Fatalf("Send after Close: %v", err)
	}
	if p, o := c.Identity(); p != pcode || o != oid {
		t.Fatal("Close changed the immutable identity")
	}
}

func TestNewClientValidationAndRedaction(t *testing.T) {
	if hash.HashStr("oid-zero-36v1Np") != 0 {
		t.Fatal("invalid zero-OID fixture")
	}
	cases := map[string]func(*Config){
		"empty key":        func(c *Config) { c.AccessKey = "" },
		"malformed key":    func(c *Config) { c.AccessKey = "SYNTHETIC_SECRET_DO_NOT_ECHO" },
		"zero pcode":       func(c *Config) { c.AccessKey = syntheticLicense(0, []byte(testMasterKey)) },
		"no servers":       func(c *Config) { c.Servers = nil },
		"many servers":     func(c *Config) { c.Servers = make([]string, 33) },
		"zero timeout":     func(c *Config) { c.Timeout = 0 },
		"negative timeout": func(c *Config) { c.Timeout = -time.Second },
		"empty object":     func(c *Config) { c.ObjectName = "" },
		"object spaces":    func(c *Config) { c.ObjectName = "   " },
		"object prefix":    func(c *Config) { c.ObjectName = " node" },
		"object suffix":    func(c *Config) { c.ObjectName = "node " },
		"object newline":   func(c *Config) { c.ObjectName = "node\nname" },
		"object nul":       func(c *Config) { c.ObjectName = "node\x00name" },
		"object utf8":      func(c *Config) { c.ObjectName = "node\xffname" },
		"object invisible": func(c *Config) { c.ObjectName = "node\u200bname" },
		"long object":      func(c *Config) { c.ObjectName = strings.Repeat("a", 513) },
		"zero oid":         func(c *Config) { c.ObjectName = "oid-zero-36v1Np" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig()
			change(&cfg)
			c, err := NewClient(cfg)
			if err == nil {
				_ = c.Close()
				t.Fatal("accepted invalid configuration")
			}
			if cfg.AccessKey != "" && strings.Contains(err.Error(), cfg.AccessKey) {
				t.Fatal("configuration error exposed access key")
			}
		})
	}
	for _, server := range []string{
		"", ":6600", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:-1", "127.0.0.1:65536", "127.0.0.1:http", "127.0.0.1:+6600",
		" 127.0.0.1:6600", "127.0.0.1:6600\n", "http://127.0.0.1:6600", "user@host:6600", "host/path:6600", "host#secret:6600",
		"bad..host:6600", "-host:6600", "host-:6600", "host_name:6600", "한글:6600", "999.0.0.1:6600", "127.1:6600",
		"0.0.0.0:6600", "224.0.0.1:6600", "255.255.255.255:6600", "[::]:6600", "[::ffff:0.0.0.0]:6600", "[ff02::1]:6600",
		"[::1%bad/zone]:6600", "[127.0.0.1]:6600", "[hostname]:6600", "::1:6600", strings.Repeat("a", 64) + ":6600",
	} {
		cfg := testConfig()
		cfg.Servers = []string{server}
		if c, err := NewClient(cfg); err == nil {
			_ = c.Close()
			t.Errorf("accepted malformed server %q", server)
		}
	}
	for _, server := range []string{"127.0.0.1:1", "127.0.0.1:65535", "collector.invalid:6600", "Collector.invalid.:6600", "localhost:6600", "[::1]:6600", "[fe80::1%en0]:6600"} {
		cfg := testConfig()
		cfg.Servers = []string{server}
		c := testClient(t, cfg) // Validation only: never resolve or dial a hostname.
		if p, o := c.Identity(); p != testPcode || o != hash.HashStr(cfg.ObjectName) {
			t.Fatal("server selection affected identity")
		}
	}
}

func TestSendRejectsInvalidPackBeforeDial(t *testing.T) {
	c := testClient(t, testConfig())
	var dials atomic.Int32
	c.dialContext = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("unexpected dial")
	}
	wrongPcode, wrongOID := testPack(1), testPack(1)
	wrongPcode.Pcode = testPcode + 1
	wrongOID.Oid = hash.HashStr(testConfig().ObjectName) + 1
	missingTags, missingData := testPack(1), testPack(1)
	missingTags.Tags, missingData.Data = nil, nil
	oversized := testPack(1)
	oversized.Put("too much", strings.Repeat("x", maxFrameBody+1))
	for _, p := range []*pack.TagCountPack{nil, {}, wrongPcode, wrongOID, missingTags, missingData, oversized} {
		if err := c.Send(context.Background(), p); err == nil || errors.Is(err, ErrAmbiguousDelivery) {
			t.Fatalf("invalid pack: %v", err)
		}
	}
	if err := c.Send(nil, testPack(1)); err == nil {
		t.Fatal("accepted nil context")
	}
	if dials.Load() != 0 {
		t.Fatal("invalid input reached the network")
	}
}

func TestSendLoopbackAESWindowsAndReuse(t *testing.T) {
	cfg := testConfig()
	const firstWindow int64 = 1720000000123
	collector := startCollector(t, func(conn net.Conn) error {
		if err := collectorAuthenticate(conn, cfg); err != nil {
			return err
		}
		for _, wantTime := range []int64{firstWindow, 0, -1} {
			p, err := collectorPack(conn, cfg)
			if err != nil {
				return err
			}
			if p.Time != wantTime || p.Category != "synthetic_window" || p.Okind != 23 || p.Onode != 45 || p.GetTag("node") != "node-a" || p.GetTag("peer") != "127.0.0.2" || p.GetLong("count") != 3 || p.GetLong("bytes") != 456 || p.GetFloat("latency") != 12.5 || p.Data.GetString("state") != "ok" {
				return fmt.Errorf("window identity, time, or data did not survive serialization")
			}
			// Invalid pack contents must never be decoded as remote commands.
			command := collectorFrame(4, 0x02, testPcode, hash.HashStr(cfg.ObjectName), testTransfer, make([]byte, 16))
			if _, err := conn.Write(command); err != nil {
				return err
			}
			clock := collectorFrame(3, 0xfe, testPcode, hash.HashStr(cfg.ObjectName), 0, make([]byte, 16))
			if _, err := conn.Write(clock); err != nil {
				return err
			}
		}
		return nil
	})
	clientCfg := cfg
	clientCfg.Servers = []string{collector.address()}
	c := testClient(t, clientCfg)
	for i, window := range []int64{firstWindow, 0, -1} {
		p := testPack(window)
		if i == 1 {
			p.Pcode, p.Oid = c.Identity()
		}
		before := p.AbstractPack
		if err := c.Send(context.Background(), p); err != nil {
			t.Fatal(err)
		}
		if p.AbstractPack != before || p.GetTagHash() != 0 {
			t.Fatal("Send mutated the caller's pack")
		}
	}
	collector.wait(t)
}

func TestConcurrentSendReusesOneConnection(t *testing.T) {
	const count = 32
	cfg := testConfig()
	collector := startCollector(t, func(conn net.Conn) error {
		if err := collectorAuthenticate(conn, cfg); err != nil {
			return err
		}
		for i := 0; i < count; i++ {
			p, err := collectorPack(conn, cfg)
			if err != nil || p.Time != 12345 || p.GetLong("count") != 3 {
				return fmt.Errorf("concurrent window %d: %v", i, err)
			}
		}
		return nil
	})
	clientCfg := cfg
	clientCfg.Servers = []string{collector.address()}
	c := testClient(t, clientCfg)
	p := testPack(12345)
	var wg sync.WaitGroup
	results := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- c.Send(context.Background(), p)
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Error(err)
		}
	}
	if p.GetTagHash() != 0 || p.Pcode != 0 || p.Oid != 0 {
		t.Fatal("concurrent Send mutated shared input")
	}
	collector.wait(t)
}
