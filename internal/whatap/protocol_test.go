package whatap

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestECBKnownVectorAndPadding(t *testing.T) {
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	plain, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	want, _ := hex.DecodeString("69c4e0d86a7b0430d8cdb78070b4c55a")
	block := masterCipher(key)
	if got := encryptECB(block, plain); !bytes.Equal(got, want) {
		t.Fatalf("AES-128 compatibility vector: %x", got)
	}
	got, err := decryptECB(block, want)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("AES decrypt: %v", err)
	}
	for _, size := range []int{1, 15, 16, 17, 31, 32} {
		input := bytes.Repeat([]byte{7}, size)
		encrypted := encryptECB(block, input)
		decoded, err := decryptECB(block, encrypted)
		if err != nil || len(encrypted) != (size+15)/16*16 || !bytes.Equal(decoded[:size], input) || !bytes.Equal(decoded[size:], make([]byte, len(decoded)-size)) {
			t.Fatalf("zero padding at size %d", size)
		}
	}
	for _, input := range [][]byte{nil, make([]byte, 15), make([]byte, 17)} {
		if _, err := decryptECB(block, input); err == nil {
			t.Fatal("accepted a partial AES block")
		}
	}
	for _, size := range []int{1, 15, 16, 17, 32, 1024} {
		key := bytes.Repeat([]byte{0x72}, size)
		normalized := make([]byte, 16)
		copy(normalized, key)
		if !bytes.Equal(encryptECB(masterCipher(key), plain), encryptECB(masterCipher(normalized), plain)) {
			t.Fatalf("master key normalization at length %d", size)
		}
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }

func TestWriteAll(t *testing.T) {
	input := []byte("short writes must preserve all bytes")
	var output bytes.Buffer
	w := writerFunc(func(data []byte) (int, error) {
		n := 3
		if len(data) < n {
			n = len(data)
		}
		return output.Write(data[:n])
	})
	if n, err := writeAll(w, input); err != nil || n != len(input) || !bytes.Equal(output.Bytes(), input) {
		t.Fatalf("short writes: n=%d err=%v", n, err)
	}
	broken := errors.New("synthetic write failure")
	for _, tc := range []struct {
		name string
		n    int
		err  error
		want error
	}{
		{"no progress", 0, nil, io.ErrNoProgress},
		{"negative count", -1, nil, io.ErrShortWrite},
		{"excess count", len(input) + 1, nil, io.ErrShortWrite},
		{"zero plus error", 0, broken, broken},
		{"partial plus error", 7, broken, broken},
		{"complete plus error", len(input), broken, broken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			_, err := writeAll(writerFunc(func([]byte) (int, error) {
				calls++
				return tc.n, tc.err
			}), input)
			if !errors.Is(err, tc.want) || calls != 1 {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestWatchConnectionStopIsIdempotent(t *testing.T) {
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &session{conn: conn, closed: make(chan struct{})}
	stop := watchConnection(ctx, s)
	stop()
	done := make(chan struct{})
	go func() {
		stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("stopping an already stopped cancellation callback blocked")
	}
	cancel()
	if s.isClosed() {
		t.Fatal("cancel after stopping affected a reusable connection")
	}
}

func FuzzKeyReply(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 16))
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 1025))
	f.Add(collectorEncrypt([]byte(testMasterKey), collectorKeyPlain()))
	f.Add(collectorEncrypt([]byte(testMasterKey), []byte{0, 0, 0, 1, 254, 127, 255, 255, 255}))
	c := &Client{master: masterCipher([]byte("synthetic-master"))}
	f.Fuzz(func(t *testing.T, body []byte) {
		key, block, err := c.decodeKeyReply(body)
		if err == nil && (key == 0 || block == nil || block.BlockSize() != 16) {
			t.Fatal("invalid successful key reply")
		}
	})
}
