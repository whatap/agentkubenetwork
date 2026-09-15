package l7

import (
	"encoding/binary"
	"testing"

	"github.com/whatap/agentkubenetwork/internal/flow"
	"golang.org/x/net/http2/hpack"
)

func TestHTTP2BufferedIdentityAcrossFramesAndContinuation(t *testing.T) {
	for _, known := range []bool{false, true} {
		name := "unknown_to_B"
		if known {
			name = "A_to_B"
		}
		t.Run(name, func(t *testing.T) {
			state := newHTTP2DirectionState(65536, 16384)
			encoder := newHPACKTestEncoder(t)
			headers := func(id uint32) []byte {
				return http2TestHeadersFrame(t, encoder, id, hpack.HeaderField{Name: ":method", Value: "GET"}, hpack.HeaderField{Name: ":path", Value: "/multi"})
			}
			one, three, five, seven := headers(1), headers(3), headers(5), headers(7)
			block := three[9:]
			head := rawHTTP2IdentityFrame(http2FrameHeaders, 0, 3, block[:len(block)/2])
			continuation := rawHTTP2IdentityFrame(http2FrameContinuation, http2FlagEndHeaders, 3, block[len(block)/2:])
			identity := func(name string) Fragment {
				return Fragment{Process: &flow.Process{PID: 42, ContainerID: name, Cmdline: "secret"}, DestinationResolved: &flow.ResolvedEndpoint{Address: name}}
			}
			first := Fragment{}
			if known {
				first = identity("A")
			}
			feed := func(payload []byte, ts uint64, observation Fragment) []http2HeaderBlock {
				t.Helper()
				blocks, err := state.feed(payload, ts, observation)
				if err != nil {
					t.Fatal(err)
				}
				return blocks
			}
			check := func(block http2HeaderBlock, stream uint32, ts uint64, name string) {
				t.Helper()
				if block.streamID != stream || block.startedNS != ts {
					t.Errorf("wrong first-byte clock/stream: %+v want stream=%d time=%d", block, stream, ts)
				}
				if name == "" {
					if block.identity.process != nil || block.identity.destination != nil {
						t.Errorf("unknown first byte enriched: %+v", block.identity)
					}
				} else if block.identity.process == nil || block.identity.process.ContainerID != name || block.identity.process.Cmdline != "" || block.identity.destination == nil || block.identity.destination.Address != name {
					t.Errorf("first-byte identity lost: process=%+v destination=%+v want %s", block.identity.process, block.identity.destination, name)
				}
			}
			if got := feed(one[:2], 0, first); len(got) != 0 {
				t.Fatal(got)
			}
			if known {
				first.Process.ContainerID = "mutated"
				first.DestinationResolved.Address = "mutated"
			}
			b := identity("B")
			got := feed(append(append([]byte{}, one[2:]...), head[:7]...), 2, b)
			if len(got) != 1 {
				t.Fatal(got)
			}
			want := ""
			if known {
				want = "A"
			}
			check(got[0], 1, 0, want)
			b.Process.ContainerID = "mutated"
			b.DestinationResolved.Address = "mutated"
			if got := feed(append(append([]byte{}, head[7:]...), continuation[:5]...), 3, identity("C")); len(got) != 0 {
				t.Fatal(got)
			}
			payload := append(append(append([]byte{}, continuation[5:]...), five...), seven[:8]...)
			d := identity("D")
			got = feed(payload, 4, d)
			if len(got) != 2 {
				t.Fatal(got)
			}
			check(got[0], 3, 2, "B")
			check(got[1], 5, 4, "D")
			d.Process.ContainerID = "mutated"
			d.DestinationResolved.Address = "mutated"
			got = feed(seven[8:], 5, identity("E"))
			if len(got) != 1 {
				t.Fatal(got)
			}
			check(got[0], 7, 4, "D")
		})
	}
}

func rawHTTP2IdentityFrame(kind, flags byte, stream uint32, payload []byte) []byte {
	frame := make([]byte, 9+len(payload))
	frame[0], frame[1], frame[2] = byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload))
	frame[3], frame[4] = kind, flags
	binary.BigEndian.PutUint32(frame[5:9], stream)
	copy(frame[9:], payload)
	return frame
}
