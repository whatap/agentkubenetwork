package l7

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/whatap/agentkubenetwork/internal/flow"
	"golang.org/x/net/http2/hpack"
)

const (
	http2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

	http2FrameHeaders      = 0x1
	http2FrameContinuation = 0x9

	http2FlagEndHeaders = 0x4
	http2FlagPadded     = 0x8
	http2FlagPriority   = 0x20

	defaultMaxHTTP2BufferedBytes = 64 << 10
	defaultMaxHTTP2HeaderBlock   = 16 << 10
	defaultMaxHTTP2DynamicTable  = 4096
	DropInvalidHTTP2             = "invalid_http2"
	DropHTTP2HeaderBlockTooLarge = "http2_header_block_too_large"
	DropHTTP2StreamDesync        = "http2_stream_desync"
	DropInvalidLatency           = "invalid_latency"
)

type transportKey struct {
	NodeName    string
	ObserverPID uint32
	Source      Source
	Low         flow.Endpoint
	High        flow.Endpoint
}

type directionKey struct {
	Transport transportKey
	From      flow.Endpoint
	To        flow.Endpoint
}

type http2StreamKey struct {
	Connection connectionKey
	StreamID   uint32
}

type pendingHTTP2 struct {
	startedNS uint64
	method    string
	path      string
	identity  observationIdentity
}

type http2HeaderBlock struct {
	streamID  uint32
	startedNS uint64
	fields    []hpack.HeaderField
	identity  observationIdentity
}

type http2DirectionState struct {
	buffer               []byte
	lastSeenNS           uint64
	poisoned             bool
	continuationStream   uint32
	continuationStarted  uint64
	continuationIdentity observationIdentity
	continuationBlock    []byte
	decoder              *hpack.Decoder
	maxBufferedBytes     int
	maxHeaderBlockBytes  int
}

func newHTTP2DirectionState(maxBufferedBytes, maxHeaderBlockBytes int) *http2DirectionState {
	return &http2DirectionState{
		decoder:             hpack.NewDecoder(defaultMaxHTTP2DynamicTable, nil),
		maxBufferedBytes:    maxBufferedBytes,
		maxHeaderBlockBytes: maxHeaderBlockBytes,
	}
}

func (state *http2DirectionState) feed(payload []byte, timestampNS uint64, observation Fragment) ([]http2HeaderBlock, error) {
	state.lastSeenNS = timestampNS
	if len(state.buffer)+len(payload) > state.maxBufferedBytes {
		state.resetFrameState()
		return nil, errors.New(DropInvalidHTTP2)
	}
	state.buffer = append(state.buffer, payload...)

	var blocks []http2HeaderBlock
	for {
		if len(state.buffer) < 9 {
			return blocks, nil
		}
		length := int(state.buffer[0])<<16 | int(state.buffer[1])<<8 | int(state.buffer[2])
		if length > state.maxBufferedBytes {
			state.resetFrameState()
			return blocks, errors.New(DropInvalidHTTP2)
		}
		if len(state.buffer) < 9+length {
			return blocks, nil
		}

		frameType := state.buffer[3]
		flags := state.buffer[4]
		streamID := binary.BigEndian.Uint32(state.buffer[5:9]) & 0x7fffffff
		framePayload := state.buffer[9 : 9+length]
		state.buffer = state.buffer[9+length:]

		switch frameType {
		case http2FrameHeaders:
			if streamID == 0 || state.continuationStream != 0 {
				state.resetHeaderBlock()
				return blocks, errors.New(DropInvalidHTTP2)
			}
			fragment, err := http2HeadersFragment(framePayload, flags)
			if err != nil {
				return blocks, err
			}
			if len(fragment) > state.maxHeaderBlockBytes {
				return blocks, errors.New(DropHTTP2HeaderBlockTooLarge)
			}
			if flags&http2FlagEndHeaders != 0 {
				fields, err := state.decoder.DecodeFull(fragment)
				if err != nil {
					return blocks, fmt.Errorf("%s: %w", DropInvalidHTTP2, err)
				}
				blocks = append(blocks, http2HeaderBlock{streamID: streamID, startedNS: timestampNS, fields: fields, identity: identityFrom(observation)})
				continue
			}
			state.continuationStream = streamID
			state.continuationStarted = timestampNS
			// Snapshot the HEADERS identity, including nil; later fragments
			// must not enrich or mutate the identity at this start boundary.
			state.continuationIdentity = identityFrom(observation)
			state.continuationBlock = append(state.continuationBlock[:0], fragment...)

		case http2FrameContinuation:
			if streamID == 0 || streamID != state.continuationStream {
				state.resetHeaderBlock()
				return blocks, errors.New(DropInvalidHTTP2)
			}
			if len(state.continuationBlock)+len(framePayload) > state.maxHeaderBlockBytes {
				state.resetHeaderBlock()
				return blocks, errors.New(DropHTTP2HeaderBlockTooLarge)
			}
			state.continuationBlock = append(state.continuationBlock, framePayload...)
			if flags&http2FlagEndHeaders == 0 {
				continue
			}
			fields, err := state.decoder.DecodeFull(state.continuationBlock)
			if err != nil {
				state.resetHeaderBlock()
				return blocks, fmt.Errorf("%s: %w", DropInvalidHTTP2, err)
			}
			blocks = append(blocks, http2HeaderBlock{
				streamID:  streamID,
				startedNS: state.continuationStarted,
				fields:    fields,
				identity:  state.continuationIdentity,
			})
			state.resetHeaderBlock()
		}
	}
}

func (state *http2DirectionState) resetHeaderBlock() {
	state.continuationStream = 0
	state.continuationStarted = 0
	state.continuationIdentity = observationIdentity{}
	state.continuationBlock = nil
}

func (state *http2DirectionState) resetFrameState() {
	state.buffer = nil
	state.resetHeaderBlock()
}

func (state *http2DirectionState) poison() {
	state.poisoned = true
	state.resetFrameState()
}

func http2HeadersFragment(payload []byte, flags byte) ([]byte, error) {
	if flags&http2FlagPadded != 0 {
		if len(payload) == 0 {
			return nil, errors.New(DropInvalidHTTP2)
		}
		padding := int(payload[0])
		payload = payload[1:]
		if padding > len(payload) {
			return nil, errors.New(DropInvalidHTTP2)
		}
		payload = payload[:len(payload)-padding]
	}
	if flags&http2FlagPriority != 0 {
		if len(payload) < 5 {
			return nil, errors.New(DropInvalidHTTP2)
		}
		payload = payload[5:]
	}
	return payload, nil
}

func http2Identity(fields []hpack.HeaderField, maxPathBytes int) (method, path string, status uint16, ok bool) {
	for _, field := range fields {
		switch field.Name {
		case ":method":
			method = field.Value
		case ":path":
			path = field.Value
		case ":status":
			parsed, err := strconv.ParseUint(field.Value, 10, 16)
			if err == nil && parsed >= 100 && parsed <= 599 {
				status = uint16(parsed)
			}
		}
	}
	if query := strings.IndexByte(path, '?'); query >= 0 {
		path = path[:query]
	}
	if len(path) > maxPathBytes {
		path = path[:maxPathBytes]
	}
	return method, path, status, (method != "" && path != "") || status != 0
}

func makeTransportKey(fragment Fragment) transportKey {
	low, high := fragment.SourceEndpoint, fragment.DestinationEndpoint
	if endpointLess(high, low) {
		low, high = high, low
	}
	return transportKey{
		NodeName:    fragment.NodeName,
		ObserverPID: fragment.ObserverPID,
		Source:      fragment.Source,
		Low:         low,
		High:        high,
	}
}

func endpointLess(left, right flow.Endpoint) bool {
	if left.Address != right.Address {
		return left.Address < right.Address
	}
	return left.Port < right.Port
}
