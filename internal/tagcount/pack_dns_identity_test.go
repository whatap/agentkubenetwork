package tagcount

import (
	"github.com/whatap/agentkubenetwork/internal/flow"
	"testing"
)

func TestPackForDNSPreservesObservedContainerAndTranslatedTuples(t *testing.T) {
	tx := eventDNS()
	tx.ObserverPID = 42
	tx.Process = &flow.Process{PID: 42, ContainerID: "container-at-query", Comm: "private-command", Cmdline: "private-argument"}
	tx.ClientResolved = &flow.ResolvedEndpoint{Address: "10.1.1.2", Port: 40001, Via: "conntrack"}
	tx.ServerResolved = &flow.ResolvedEndpoint{Address: "10.2.2.3", Port: 5353, Via: "conntrack"}
	p, err := PackForDNS(tx, 3895, 71)
	if err != nil {
		t.Fatal(err)
	}
	if p.Tags.GetString("observer_container_id") != "container-at-query" || p.Data.GetLong("observer_pid") != 42 {
		t.Fatal("DNS observer identity was discarded")
	}
	if p.Tags.GetString("client_resolved_addr") != "10.1.1.2" || p.Data.GetLong("client_resolved_port") != 40001 || p.Tags.GetString("server_resolved_addr") != "10.2.2.3" || p.Data.GetLong("server_resolved_port") != 5353 {
		t.Fatal("DNS translated tuples were discarded")
	}
	if p.Tags.Get("cmdline") != nil || p.Tags.Get("comm") != nil {
		t.Fatal("private process text escaped")
	}
}
