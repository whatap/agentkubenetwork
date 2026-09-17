package main

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/collector"
	"github.com/whatap/agentkubenetwork/internal/flow"
	"github.com/whatap/agentkubenetwork/internal/tagcount"
	xio "github.com/whatap/golib/io"
	"github.com/whatap/golib/lang/pack"
	"github.com/whatap/golib/util/hash"
)

type tagcountSampleReader struct {
	read bool
	stop chan struct{}
	once sync.Once
}

func (r *tagcountSampleReader) Read() (collector.Event, error) {
	if r.read {
		<-r.stop
		return collector.Event{}, io.EOF
	}
	r.read = true
	return collector.Event{Kind: collector.EventKindTCPSample, Family: collector.AddressFamilyIPv4, Protocol: collector.ProtocolTCP,
		SourceAddress: [16]byte{10, 0, 0, 1}, SourcePort: 40000, DestinationAddress: [16]byte{10, 0, 0, 2}, DestinationPort: 8080, SRTTMicros: 25}, nil
}
func (r *tagcountSampleReader) Close() error {
	r.once.Do(func() { close(r.stop) })
	return nil
}

func TestCLIDirectTagCountEndToEnd(t *testing.T) {
	listener := setTagCountTestConfig(t)
	if err := listener.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := &tagcountSampleReader{stop: make(chan struct{})}
	t.Cleanup(func() { reader.Close() })
	type result struct {
		packet *pack.TagCountPack
		err    error
	}
	received := make(chan result, 1)
	go func() {
		p, err := receiveCLITestTagCount(listener, reader.Close)
		received <- result{p, err}
	}()
	var output bytes.Buffer
	err := runArgs([]string{"-source=ebpf", "-pod-identity=false", "-node-name=node", "-conntrack=false", "-process=false", "-stdout=jsonl", "-output-mode=windows", "-window=10ms", "-allowed-lateness=0", "-duration=2s", "-export=tagcount", "-tagcount-timeout=1s", "-tagcount-drain-timeout=1s"}, bytes.NewReader(nil), &output, func(collector.OpenOptions) (collector.EventReader, error) {
		return reader, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var got result
	select {
	case got = <-received:
	case <-time.After(3 * time.Second):
		t.Fatal("local collector did not finish")
	}
	if got.err != nil {
		t.Fatal(got.err)
	}
	var window flow.Window
	decoder := json.NewDecoder(&output)
	if err := decoder.Decode(&window); err != nil {
		t.Fatal(err)
	}
	if window.SchemaVersion != flow.SchemaVersion || window.Partial || window.RTT.Count != 1 || window.RTT.SumMicros != 25 {
		t.Fatalf("unexpected producer window: %+v", window)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		t.Fatalf("unexpected extra window: %v", err)
	}
	p := got.packet
	if p.Category != tagcount.Category || p.Pcode != 123 || p.Oid != hash.HashStr("kube-network-node") || p.Time != window.WindowStart.UnixMilli() {
		t.Fatalf("TagCount identity/time mismatch: %+v", p)
	}
	for key, want := range map[string]string{"schema": "network.edge.window/v1alpha1", "observer_node": "node", "protocol": "tcp", "src_addr": "10.0.0.1", "dst_addr": "10.0.0.2", "observer_role": "unknown"} {
		if got := p.Tags.GetString(key); got != want {
			t.Errorf("tag %s = %q, want %q", key, got, want)
		}
	}
	for key, want := range map[string]int64{"src_port": 40000, "dst_port": 8080, "window_start_ms": window.WindowStart.UnixMilli(), "window_end_ms": window.WindowEnd.UnixMilli(), "srtt_count": 1, "srtt_sum_us": 25, "srtt_min_us": 25, "srtt_max_us": 25} {
		if got := p.Data.GetLong(key); got != want {
			t.Errorf("field %s = %d, want %d", key, got, want)
		}
	}
	if p.Tags.Size() != 6 || p.Data.Size() != 8 {
		t.Fatal("unexpected backend tags or fields")
	}
}

// A test-only collector exercises the actual CLI, aggregation, queue, codec
// and TCP transport. It is not a Java fixture or a real WhaTap backend.
func receiveCLITestTagCount(listener *net.TCPListener, captureDone func() error) (*pack.TagCountPack, error) {
	conn, err := listener.AcceptTCP()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return nil, err
	}
	header, body, err := readCLITestFrame(conn)
	if err != nil {
		return nil, err
	}
	if header[0] != 1 || header[1] != 0xff || binary.BigEndian.Uint64(header[2:10]) != 123 || int32(binary.BigEndian.Uint32(header[10:14])) != hash.HashStr("kube-network-node") || binary.BigEndian.Uint32(header[14:18]) != 0 {
		return nil, errors.New("unexpected key-reset header")
	}
	plain, err := cliTestCipher(body, []byte("0123456789abcdef"), false)
	if err != nil {
		return nil, err
	}
	hello := xio.NewDataInputX(plain)
	if hello.ReadText() != "hello" || hello.ReadText() != "kube-network-node" {
		return nil, errors.New("unexpected authentication hello")
	}
	sessionKey := []byte("fedcba9876543210")
	reply := xio.NewDataOutputX()
	reply.WriteInt(31337)
	reply.WriteBlob(sessionKey)
	reply.WriteInt(0)
	reply.WriteInt(0)
	response, err := cliTestCipher(reply.ToByteArray(), []byte("0123456789abcdef"), true)
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint32(header[18:22], uint32(len(response)))
	frame := append(header, response...)
	for len(frame) > 0 {
		n, err := conn.Write(frame)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, io.ErrShortWrite
		}
		frame = frame[n:]
	}
	header, body, err = readCLITestFrame(conn)
	if err != nil {
		return nil, err
	}
	if header[0] != 1 || header[1] != 2 || binary.BigEndian.Uint64(header[2:10]) != 123 || int32(binary.BigEndian.Uint32(header[10:14])) != hash.HashStr("kube-network-node") || binary.BigEndian.Uint32(header[14:18]) != 31337 {
		return nil, errors.New("unexpected encrypted TagCount header")
	}
	plain, err = cliTestCipher(body, sessionKey, false)
	if err != nil {
		return nil, err
	}
	p, ok := pack.ToPack(plain).(*pack.TagCountPack)
	if !ok {
		return nil, errors.New("collector did not receive a TagCountPack")
	}
	if err := captureDone(); err != nil {
		return nil, err
	}
	n, err := io.Copy(io.Discard, conn)
	if err != nil || n != 0 {
		return nil, fmt.Errorf("session did not close cleanly: extra bytes=%d: %v", n, err)
	}
	return p, nil
}

func readCLITestFrame(reader io.Reader) ([]byte, []byte, error) {
	header := make([]byte, 22)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, nil, err
	}
	n := binary.BigEndian.Uint32(header[18:22])
	if n == 0 || n > 65536 {
		return nil, nil, errors.New("test frame size out of bounds")
	}
	body := make([]byte, n)
	_, err := io.ReadFull(reader, body)
	return header, body, err
}

func cliTestCipher(data, key []byte, encrypt bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if encrypt {
		data = append(bytes.Clone(data), make([]byte, (aes.BlockSize-len(data)%aes.BlockSize)%aes.BlockSize)...)
	} else if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, errors.New("invalid test ciphertext length")
	}
	result := make([]byte, len(data))
	for offset := 0; offset < len(data); offset += aes.BlockSize {
		if encrypt {
			block.Encrypt(result[offset:offset+aes.BlockSize], data[offset:offset+aes.BlockSize])
		} else {
			block.Decrypt(result[offset:offset+aes.BlockSize], data[offset:offset+aes.BlockSize])
		}
	}
	return result, nil
}
