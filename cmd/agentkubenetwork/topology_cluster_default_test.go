package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/app"
	"github.com/whatap/agentkubenetwork/internal/collector"
	"github.com/whatap/agentkubenetwork/internal/topology"
)

// One WhaTap Kubernetes project monitors one cluster, so the topology cluster ID
// is an optional display name that defaults to the access key's project code.

func TestCLITopologyClusterIDIsOptional(t *testing.T) {
	clearLoggingEnvironment(t)
	clearTopologyEnvironment(t)
	err := runArgs([]string{"-source=ebpf", "-export=tagcount", "-topology-summary"}, strings.NewReader(""), io.Discard,
		func(collector.OpenOptions) (collector.EventReader, error) { return &cliEventReader{}, nil })
	if err != nil && strings.Contains(err.Error(), "topology-cluster-id") {
		t.Fatalf("unset topology cluster ID was rejected: %v", err)
	}
}

func TestDefaultTopologyClusterIDUsesTheProjectCodeOnlyWhenUnset(t *testing.T) {
	if defaultTopologyClusterID(nil, 12345) != nil {
		t.Fatal("disabled topology was enabled")
	}
	unset := &topology.Config{WindowSize: time.Minute, MaxEntries: 16}
	got := defaultTopologyClusterID(unset, 12345)
	if got.ClusterID != "12345" || got.WindowSize != time.Minute || got.MaxEntries != 16 {
		t.Fatalf("unset cluster ID did not become the project code: %+v", got)
	}
	if unset.ClusterID != "" {
		t.Fatal("caller configuration was mutated")
	}
	named := &topology.Config{ClusterID: "prod-seoul", WindowSize: time.Minute, MaxEntries: 16}
	if got := defaultTopologyClusterID(named, 12345); got.ClusterID != "prod-seoul" {
		t.Fatalf("explicit cluster ID was replaced: %+v", got)
	}
}

func TestTagCountRunDefaultsTopologyClusterIDToTheLicenseProjectCode(t *testing.T) {
	setTagCountTestConfig(t)
	var summary bytes.Buffer
	unset := &topology.Config{WindowSize: time.Minute, MaxEntries: 16}
	config := bpfRunConfig{NodeName: "node", Events: app.EventOptions{OutputMode: "windows", WindowSize: 5 * time.Second,
		AllowedLateness: time.Second, Topology: unset}}
	reader := &noEventReader{}
	// topology.New rejects an empty cluster ID, so this run only starts if the
	// license project code was filled in before the pipeline was built. With no
	// events nothing is sent, so the fake collector never has to answer.
	err := runTagCount(context.Background(), io.Discard, &summary, func(collector.OpenOptions) (collector.EventReader, error) {
		return reader, nil
	}, config, tagcountRunOptions{QueueCapacity: 4, Timeout: time.Second, DrainTimeout: time.Second})
	if err != nil {
		t.Fatalf("unset topology cluster ID did not default to the project code: %v (summary %s)", err, summary.String())
	}
	if !reader.closed {
		t.Fatal("event pipeline did not run")
	}
	if unset.ClusterID != "" {
		t.Fatal("caller configuration was mutated")
	}
}

type noEventReader struct{ closed bool }

func (r *noEventReader) Read() (collector.Event, error) { return collector.Event{}, io.EOF }
func (r *noEventReader) Close() error                   { r.closed = true; return nil }
