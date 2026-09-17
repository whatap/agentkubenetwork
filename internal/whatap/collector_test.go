package whatap

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	whatapio "github.com/whatap/golib/io"
	"github.com/whatap/golib/lang/pack"
	"github.com/whatap/golib/util/hash"
)

const (
	testPcode      int64 = 112233445566
	testMasterKey        = "synthetic-master"
	testSessionKey       = "0123456789abcdef"
	testTransfer   int32 = 0x01020304
)

func testConfig() Config {
	return Config{
		AccessKey: syntheticLicense(testPcode, []byte(testMasterKey)),
		Servers:   []string{"127.0.0.1:1"}, ObjectName: "synthetic-node/테스트-a", Timeout: 2 * time.Second,
	}
}

func testClient(t *testing.T, cfg Config) *Client {
	t.Helper()
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func testPack(window int64) *pack.TagCountPack {
	p := pack.NewTagCountPack()
	p.Category = "synthetic_window"
	p.Time, p.Okind, p.Onode = window, 23, 45
	p.PutTag("node", "node-a")
	p.PutTag("peer", "127.0.0.2")
	p.Put("count", int64(3))
	p.Put("bytes", int64(456))
	p.Put("latency", 12.5)
	p.Put("state", "ok")
	return p
}

type fakeCollector struct {
	listener *net.TCPListener
	done     chan struct{}
	err      error
	mu       sync.Mutex
	conn     net.Conn
	closed   bool
}

func startCollector(t *testing.T, serve func(net.Conn) error) *fakeCollector {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeCollector{listener: listener, done: make(chan struct{})}
	t.Cleanup(func() {
		f.mu.Lock()
		f.closed = true
		conn := f.conn
		f.mu.Unlock()
		_ = listener.Close()
		if conn != nil {
			_ = conn.Close()
		}
		select {
		case <-f.done:
		case <-time.After(3 * time.Second):
			t.Error("fake collector did not stop")
		}
	})
	go func() {
		defer close(f.done)
		conn, err := listener.Accept()
		if err != nil {
			f.err = err
			return
		}
		defer conn.Close()
		f.mu.Lock()
		f.conn = conn
		closed := f.closed
		f.mu.Unlock()
		if closed {
			return
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		f.err = serve(conn)
	}()
	return f
}

func (f *fakeCollector) address() string { return f.listener.Addr().String() }

func (f *fakeCollector) wait(t *testing.T) {
	t.Helper()
	select {
	case <-f.done:
		if f.err != nil {
			t.Fatalf("fake collector: %v", f.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fake collector timed out")
	}
}

// Independent collector-side encoding: use golib's primitive writers rather
// than the transport's header or crypto helpers to avoid self-roundtrip tests.
func collectorFrame(source, code byte, pcode int64, oid, transfer int32, body []byte) []byte {
	return whatapio.NewDataOutputX().WriteByte(source).WriteByte(code).WriteLong(pcode).
		WriteInt(oid).WriteInt(transfer).WriteIntBytes(body).ToByteArray()
}

func collectorEncrypt(key []byte, plain []byte) []byte {
	var normalized [16]byte
	copy(normalized[:], key)
	block, _ := aes.NewCipher(normalized[:])
	padded := make([]byte, (len(plain)+15)/16*16)
	copy(padded, plain)
	out := make([]byte, len(padded))
	for i := 0; i < len(padded); i += 16 {
		block.Encrypt(out[i:i+16], padded[i:i+16])
	}
	return out
}

func collectorDecrypt(key []byte, encrypted []byte) ([]byte, error) {
	if len(encrypted) == 0 || len(encrypted)%16 != 0 {
		return nil, fmt.Errorf("bad collector ciphertext length: %d", len(encrypted))
	}
	var normalized [16]byte
	copy(normalized[:], key)
	block, _ := aes.NewCipher(normalized[:])
	out := make([]byte, len(encrypted))
	for i := 0; i < len(encrypted); i += 16 {
		block.Decrypt(out[i:i+16], encrypted[i:i+16])
	}
	return out, nil
}

func readCollectorFrame(conn net.Conn) ([22]byte, []byte, error) {
	var header [22]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return header, nil, err
	}
	size := binary.BigEndian.Uint32(header[18:22])
	if size == 0 || size > 8*1024*1024 {
		return header, nil, fmt.Errorf("bad collector frame length: %d", size)
	}
	body := make([]byte, int(size))
	_, err := io.ReadFull(conn, body)
	return header, body, err
}

func collectorHello(conn net.Conn, cfg Config) error {
	header, body, err := readCollectorFrame(conn)
	if err != nil {
		return err
	}
	wantHeader := collectorFrame(1, 0xff, testPcode, hash.HashStr(cfg.ObjectName), 0, body)[:22]
	if !bytes.Equal(header[:], wantHeader) {
		return fmt.Errorf("unexpected hello header: %x", header)
	}
	plain, err := collectorDecrypt([]byte(testMasterKey), body)
	if err != nil {
		return err
	}
	ip := conn.RemoteAddr().(*net.TCPAddr).IP.To4()
	want := whatapio.NewDataOutputX().WriteText("hello").WriteText(cfg.ObjectName).
		WriteInt(int32(binary.BigEndian.Uint32(ip))).ToByteArray()
	if len(plain) < len(want) || !bytes.Equal(plain[:len(want)], want) || !bytes.Equal(plain[len(want):], make([]byte, len(plain)-len(want))) {
		return fmt.Errorf("invalid AES hello or IPv4 field")
	}
	return nil
}

func collectorKeyPlain() []byte {
	return whatapio.NewDataOutputX().WriteInt(testTransfer).WriteBlob([]byte(testSessionKey)).
		WriteInt(0x12345678).WriteInt(0x7f000001).ToByteArray()
}

func collectorAuthenticate(conn net.Conn, cfg Config) error {
	if err := collectorHello(conn, cfg); err != nil {
		return err
	}
	reply := collectorFrame(3, 0xff, testPcode, hash.HashStr(cfg.ObjectName), 0,
		collectorEncrypt([]byte(testMasterKey), collectorKeyPlain()))
	_, err := conn.Write(reply)
	return err
}

func collectorPack(conn net.Conn, cfg Config) (*pack.TagCountPack, error) {
	header, body, err := readCollectorFrame(conn)
	if err != nil {
		return nil, err
	}
	wantHeader := collectorFrame(1, 0x02, testPcode, hash.HashStr(cfg.ObjectName), testTransfer, body)[:22]
	if !bytes.Equal(header[:], wantHeader) {
		return nil, fmt.Errorf("unexpected data header or repeated authentication: %x", header)
	}
	plain, err := collectorDecrypt([]byte(testSessionKey), body)
	if err != nil {
		return nil, err
	}
	if len(plain) < 2 || binary.BigEndian.Uint16(plain[:2]) != uint16(pack.TAG_COUNT) {
		return nil, fmt.Errorf("not an actual serialized TagCountPack")
	}
	p, ok := pack.ToPack(plain).(*pack.TagCountPack)
	if !ok || p.Pcode != testPcode || p.Oid != hash.HashStr(cfg.ObjectName) {
		return nil, fmt.Errorf("pack identity mismatch")
	}
	return p, nil
}

func collectorEOF(conn net.Conn) error {
	var b [1]byte
	n, err := conn.Read(b[:])
	if n != 0 || err != io.EOF {
		return fmt.Errorf("expected connection close without more data, got n=%d err=%v", n, err)
	}
	return nil
}
