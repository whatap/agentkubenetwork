package conntrack

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
)

func incompleteDumpFixture(kind string) []byte {
	entry := conntrackMessage(dnatEntryBytes())
	done := netlinkMessage(nlmsgDone, nil)
	switch kind {
	case "done_errno":
		payload := make([]byte, 4)
		code := int32(-12)
		binary.NativeEndian.PutUint32(payload, uint32(code))
		done = netlinkMessage(nlmsgDone, payload)
	case "done_interrupted":
		binary.NativeEndian.PutUint16(done[6:8], 0x10) // NLM_F_DUMP_INTR
	case "entry_interrupted":
		binary.NativeEndian.PutUint16(entry[6:8], 0x10)
	case "short_done_errno":
		done = netlinkMessage(nlmsgDone, []byte{1})
	}
	return append(entry, done...)
}

func TestParseMessagesRejectsIncompleteDump(t *testing.T) {
	for _, kind := range []string{"done_errno", "done_interrupted", "entry_interrupted", "short_done_errno"} {
		t.Run(kind, func(t *testing.T) {
			entries, done, err := parseMessages(incompleteDumpFixture(kind))
			if err == nil || done || len(entries) != 0 {
				t.Fatalf("incomplete dump published: entries=%+v done=%v err=%v", entries, done, err)
			}
		})
	}
}

func TestIncompleteDumpInvalidatesCacheAndBacksOff(t *testing.T) {
	for _, kind := range []string{"done_errno", "done_interrupted", "entry_interrupted"} {
		for _, mode := range []string{"scheduled", "miss"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				current := time.Unix(100, 0)
				calls := 0
				resolver := newResolver(func() ([]Entry, error) {
					calls++
					data := incompleteDumpFixture(kind)
					if calls == 1 {
						data = append(conntrackMessage(dnatEntryBytes()), netlinkMessage(nlmsgDone, nil)...)
					}
					entries, _, err := parseMessages(data)
					return entries, err
				}, time.Second, func() time.Time { return current })
				client := flow.Endpoint{Address: "10.131.1.173", Port: 41000}
				service := flow.Endpoint{Address: "172.30.181.224", Port: 8080}
				if _, _, ok := resolver.Resolve("tcp", client, service); !ok {
					t.Fatal("initial complete proof missing")
				}
				if mode == "scheduled" {
					current = current.Add(2 * time.Second)
					resolver.Resolve("tcp", client, service)
				} else {
					current = current.Add(30 * time.Millisecond)
					missing := client
					missing.Port++
					resolver.Resolve("tcp", missing, service)
				}
				if _, _, ok := resolver.Resolve("tcp", client, service); ok {
					t.Error("incomplete dump left positive proof")
				}
				for i := 0; i < 20; i++ {
					current = current.Add(time.Millisecond)
					resolver.Resolve("tcp", flow.Endpoint{}, service)
				}
				if calls != 2 {
					t.Errorf("missing error backoff: dumps=%d", calls)
				}
			})
		}
	}
}
