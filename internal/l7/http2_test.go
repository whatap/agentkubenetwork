package l7

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
	"golang.org/x/net/http2/hpack"
)

func TestCorrelatorHTTP2CorrelatesConcurrentStreams(t *testing.T) {
	correlator := NewCorrelator(Config{})
	client := flow.Endpoint{Address: "10.0.0.10", Port: 32000}
	server := flow.Endpoint{Address: "10.0.0.20", Port: 8443}
	requestEncoder := newHPACKTestEncoder(t)
	responseEncoder := newHPACKTestEncoder(t)

	requestOne := append([]byte(http2ClientPreface), http2TestHeadersFrame(t, requestEncoder, 1,
		hpack.HeaderField{Name: ":method", Value: "GET"},
		hpack.HeaderField{Name: ":path", Value: "/one"},
	)...)
	requestThree := http2TestHeadersFrame(t, requestEncoder, 3,
		hpack.HeaderField{Name: ":method", Value: "POST"},
		hpack.HeaderField{Name: ":path", Value: "/three"},
	)
	responseThree := http2TestHeadersFrame(t, responseEncoder, 3,
		hpack.HeaderField{Name: ":status", Value: "201"},
	)
	responseOne := http2TestHeadersFrame(t, responseEncoder, 1,
		hpack.HeaderField{Name: ":status", Value: "200"},
	)

	process := func(timestamp uint64, source, destination flow.Endpoint, payload []byte) []Output {
		return correlator.Process(Fragment{
			ObservedAt:          time.Unix(0, int64(timestamp)).UTC(),
			KernelTimestampNS:   timestamp,
			NodeName:            "worker-a",
			Source:              SourceOpenSSL,
			SourceEndpoint:      source,
			DestinationEndpoint: destination,
			Payload:             payload,
		})
	}

	if outputs := process(1_000_000, client, server, requestOne); len(outputs) != 0 {
		t.Fatalf("stream 1 request outputs = %+v", outputs)
	}
	if outputs := process(2_000_000, client, server, requestThree); len(outputs) != 0 {
		t.Fatalf("stream 3 request outputs = %+v", outputs)
	}
	outputs := process(7_000_000, server, client, responseThree)
	assertHTTP2Transaction(t, outputs, 3, "POST", "/three", 201, 5_000)
	outputs = process(11_000_000, server, client, responseOne)
	assertHTTP2Transaction(t, outputs, 1, "GET", "/one", 200, 10_000)
}

func TestCorrelatorHTTP2ReassemblesFragmentedFrame(t *testing.T) {
	correlator := NewCorrelator(Config{})
	client := flow.Endpoint{Address: "10.0.0.10", Port: 32000}
	server := flow.Endpoint{Address: "10.0.0.20", Port: 8443}
	requestEncoder := newHPACKTestEncoder(t)
	responseEncoder := newHPACKTestEncoder(t)
	request := append([]byte(http2ClientPreface), http2TestHeadersFrame(t, requestEncoder, 1,
		hpack.HeaderField{Name: ":method", Value: "GET"},
		hpack.HeaderField{Name: ":path", Value: "/fragmented"},
	)...)

	fragment := func(timestamp uint64, source, destination flow.Endpoint, payload []byte) []Output {
		return correlator.Process(Fragment{
			ObservedAt:          time.Unix(0, int64(timestamp)).UTC(),
			KernelTimestampNS:   timestamp,
			NodeName:            "worker-a",
			Source:              SourceKernelPlaintext,
			SourceEndpoint:      source,
			DestinationEndpoint: destination,
			Payload:             payload,
		})
	}

	split := len(request) - 3
	if outputs := fragment(1_000_000, client, server, request[:split]); len(outputs) != 0 {
		t.Fatalf("partial request outputs = %+v", outputs)
	}
	if outputs := fragment(2_000_000, client, server, request[split:]); len(outputs) != 0 {
		t.Fatalf("completed request outputs = %+v", outputs)
	}
	response := http2TestHeadersFrame(t, responseEncoder, 1,
		hpack.HeaderField{Name: ":status", Value: "204"},
	)
	outputs := fragment(9_000_000, server, client, response)
	assertHTTP2Transaction(t, outputs, 1, "GET", "/fragmented", 204, 7_000)
}

func TestCorrelatorExpiresIdleHTTP2ConnectionAndPendingStream(t *testing.T) {
	correlator := NewCorrelator(Config{StateTTL: time.Second, SweepEvery: 1})
	client := flow.Endpoint{Address: "10.0.0.10", Port: 32000}
	server := flow.Endpoint{Address: "10.0.0.20", Port: 8443}
	encoder := newHPACKTestEncoder(t)
	request := append([]byte(http2ClientPreface), http2TestHeadersFrame(t, encoder, 1,
		hpack.HeaderField{Name: ":method", Value: "GET"},
		hpack.HeaderField{Name: ":path", Value: "/timeout"},
	)...)
	if outputs := correlator.Process(Fragment{
		ObservedAt:          time.Unix(1, 0).UTC(),
		KernelTimestampNS:   uint64(time.Second),
		NodeName:            "worker-a",
		ObserverPID:         42,
		Source:              SourceOpenSSL,
		SourceEndpoint:      client,
		DestinationEndpoint: server,
		Payload:             request,
	}); len(outputs) != 0 {
		t.Fatalf("request outputs = %+v", outputs)
	}

	outputs := correlator.Process(Fragment{
		ObservedAt:        time.Unix(3, 0).UTC(),
		KernelTimestampNS: uint64(3 * time.Second),
		NodeName:          "worker-b",
		ObserverPID:       99,
		Source:            SourceKernelPlaintext,
		Payload:           []byte("not HTTP"),
	})
	if len(outputs) != 1 || outputs[0].Drop == nil || outputs[0].Drop.Reason != DropResponseTimeout || outputs[0].Drop.Protocol != ProtocolHTTP2 {
		t.Fatalf("expiry outputs = %+v, want HTTP/2 response timeout", outputs)
	}
	if len(correlator.http2) != 0 || len(correlator.http2Directions) != 0 || len(correlator.http2Connections) != 0 {
		t.Fatalf("expired HTTP/2 state retained: streams=%d directions=%d connections=%d", len(correlator.http2), len(correlator.http2Directions), len(correlator.http2Connections))
	}
}

func TestCorrelatorBoundsPendingHTTP2Streams(t *testing.T) {
	correlator := NewCorrelator(Config{MaxHTTP2Streams: 1})
	client := flow.Endpoint{Address: "10.0.0.10", Port: 32000}
	server := flow.Endpoint{Address: "10.0.0.20", Port: 8443}
	encoder := newHPACKTestEncoder(t)
	first := append([]byte(http2ClientPreface), http2TestHeadersFrame(t, encoder, 1,
		hpack.HeaderField{Name: ":method", Value: "GET"},
		hpack.HeaderField{Name: ":path", Value: "/one"},
	)...)
	fragment := func(timestamp uint64, payload []byte) []Output {
		return correlator.Process(Fragment{
			ObservedAt:          time.Unix(0, int64(timestamp)).UTC(),
			KernelTimestampNS:   timestamp,
			NodeName:            "worker-a",
			ObserverPID:         42,
			Source:              SourceOpenSSL,
			SourceEndpoint:      client,
			DestinationEndpoint: server,
			Payload:             payload,
		})
	}
	if outputs := fragment(1_000_000, first); len(outputs) != 0 {
		t.Fatalf("first stream outputs = %+v", outputs)
	}
	second := http2TestHeadersFrame(t, encoder, 3,
		hpack.HeaderField{Name: ":method", Value: "GET"},
		hpack.HeaderField{Name: ":path", Value: "/three"},
	)
	outputs := fragment(2_000_000, second)
	if len(outputs) != 1 || outputs[0].Drop == nil || outputs[0].Drop.Reason != DropStateCapacity {
		t.Fatalf("second stream outputs = %+v, want state capacity drop", outputs)
	}
	if len(correlator.http2) != 1 {
		t.Fatalf("pending HTTP/2 streams = %d, want 1", len(correlator.http2))
	}
}

func TestCorrelatorPoisonsHTTP2DirectionAfterTruncatedFragment(t *testing.T) {
	correlator := NewCorrelator(Config{})
	client := flow.Endpoint{Address: "10.0.0.10", Port: 32000}
	server := flow.Endpoint{Address: "10.0.0.20", Port: 8443}
	requestEncoder := newHPACKTestEncoder(t)
	responseEncoder := newHPACKTestEncoder(t)
	request := append([]byte(http2ClientPreface), http2TestHeadersFrame(t, requestEncoder, 1,
		hpack.HeaderField{Name: ":method", Value: "GET"},
		hpack.HeaderField{Name: ":path", Value: "/safe"},
	)...)
	if outputs := correlator.Process(Fragment{
		ObservedAt:          time.Unix(0, 1_000_000).UTC(),
		KernelTimestampNS:   1_000_000,
		NodeName:            "worker-a",
		ObserverPID:         42,
		Source:              SourceOpenSSL,
		SourceEndpoint:      client,
		DestinationEndpoint: server,
		TotalLength:         uint32(len(request)),
		Payload:             request,
	}); len(outputs) != 0 {
		t.Fatalf("request outputs = %+v", outputs)
	}

	response := http2TestHeadersFrame(t, responseEncoder, 1,
		hpack.HeaderField{Name: ":status", Value: "200"},
	)
	truncated := Fragment{
		ObservedAt:          time.Unix(0, 2_000_000).UTC(),
		KernelTimestampNS:   2_000_000,
		NodeName:            "worker-a",
		ObserverPID:         42,
		Source:              SourceOpenSSL,
		SourceEndpoint:      server,
		DestinationEndpoint: client,
		TotalLength:         uint32(len(response) + 128),
		Payload:             response,
	}
	outputs := correlator.Process(truncated)
	if len(outputs) != 1 || outputs[0].Drop == nil || outputs[0].Drop.Reason != DropHTTP2StreamDesync {
		t.Fatalf("truncated response outputs = %+v, want stream desync drop", outputs)
	}

	valid := truncated
	valid.ObservedAt = time.Unix(0, 3_000_000).UTC()
	valid.KernelTimestampNS = 3_000_000
	valid.TotalLength = uint32(len(response))
	if outputs := correlator.Process(valid); len(outputs) != 0 {
		t.Fatalf("poisoned direction produced output: %+v", outputs)
	}
}

type hpackTestEncoder struct {
	buffer  bytes.Buffer
	encoder *hpack.Encoder
}

func newHPACKTestEncoder(t *testing.T) *hpackTestEncoder {
	t.Helper()
	encoder := &hpackTestEncoder{}
	encoder.encoder = hpack.NewEncoder(&encoder.buffer)
	return encoder
}

func http2TestHeadersFrame(t *testing.T, encoder *hpackTestEncoder, streamID uint32, fields ...hpack.HeaderField) []byte {
	t.Helper()
	encoder.buffer.Reset()
	for _, field := range fields {
		if err := encoder.encoder.WriteField(field); err != nil {
			t.Fatalf("encode HPACK field: %v", err)
		}
	}
	block := append([]byte(nil), encoder.buffer.Bytes()...)
	frame := make([]byte, 9+len(block))
	frame[0] = byte(len(block) >> 16)
	frame[1] = byte(len(block) >> 8)
	frame[2] = byte(len(block))
	frame[3] = http2FrameHeaders
	frame[4] = http2FlagEndHeaders
	binary.BigEndian.PutUint32(frame[5:9], streamID&0x7fffffff)
	copy(frame[9:], block)
	return frame
}

func assertHTTP2Transaction(t *testing.T, outputs []Output, streamID uint32, method, path string, status uint16, latencyMicros uint64) {
	t.Helper()
	if len(outputs) != 1 || outputs[0].Transaction == nil {
		t.Fatalf("outputs = %+v, want one HTTP/2 transaction", outputs)
	}
	transaction := outputs[0].Transaction
	if transaction.Protocol != ProtocolHTTP2 || transaction.StreamID != streamID || transaction.Method != method || transaction.Path != path || transaction.StatusCode != status || transaction.ResponseLatencyMicros != latencyMicros {
		t.Fatalf("unexpected transaction: %+v", transaction)
	}
}
