package main

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
)

func TestIncompleteTupleIsSkippedWithoutDial(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	start := time.Date(2026, 9, 15, 8, 6, 35, 0, time.UTC)
	w := flow.Window{SchemaVersion: flow.SchemaVersion, WindowStart: start, WindowEnd: start.Add(5 * time.Second),
		Flow: flow.FlowKey{NodeName: "node", Protocol: "tcp", Direction: "connection",
			Source:      flow.Endpoint{Address: "10.0.0.1", Port: 33266},
			Destination: flow.Endpoint{Address: "10.0.0.2", Port: 0}},
		RTT: flow.Distribution{Count: 1, SumMicros: 151, MinMicros: 151, MaxMicros: 151}}
	encoded, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	input := string(encoded) + "\n" + `{"schemaVersion":"network.coverage/v0"}` + "\n"
	var out, diagnostics bytes.Buffer
	if exit := run([]string{"-address", listener.Addr().String()}, strings.NewReader(input), &out, &diagnostics); exit != 0 {
		t.Fatalf("incomplete tuple stopped stdin processing: %d: %s", exit, diagnostics.String())
	}
	for _, field := range []string{`"accepted":0`, `"failed":0`, `"skipped":1`, `"skipped_incomplete_tuple":1`, `"ignored":1`} {
		if !strings.Contains(out.String(), field) {
			t.Fatalf("missing %s: %s", field, out.String())
		}
	}
	if err := listener.SetDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if conn, err := listener.Accept(); err == nil {
		conn.Close()
		t.Fatal("incomplete tuple reached network")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatal(err)
	}
}
