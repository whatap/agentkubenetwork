package app

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/dns"
	"github.com/whatap/agentkubenetwork/internal/flow"
	"github.com/whatap/agentkubenetwork/internal/l7"
	"github.com/whatap/agentkubenetwork/internal/topology"
)

type recordingTopologyExporter struct {
	recordingTypedExporter
	summaries  []topology.Summary
	summaryErr error
}

func (e *recordingTopologyExporter) ExportTopology(s topology.Summary) error {
	e.summaries = append(e.summaries, s)
	return e.summaryErr
}

func topologyTestOptions(exporter WindowExporter) EventOptions {
	return EventOptions{OutputMode: "windows", WindowSize: 5 * time.Second, WindowExporter: exporter,
		Topology: &topology.Config{ClusterID: "cluster-a", WindowSize: time.Minute, MaxEntries: 16}}
}

func topologyTestHTTP(at time.Time) l7.Transaction {
	return l7.Transaction{SchemaVersion: l7.SchemaVersion, ObservedAt: at, Protocol: l7.ProtocolHTTP1,
		Source: l7.SourceKernelPlaintext, Method: "GET", StatusCode: 200,
		ResponseLatencyMicros: 1200, LatencyBoundary: l7.BoundaryResponseStatus,
		Flow: flow.FlowKey{NodeName: "node", Protocol: "tcp", Direction: "client-to-server",
			Source: flow.Endpoint{Address: "10.0.0.1", Port: 40000}, Destination: flow.Endpoint{Address: "10.0.0.2", Port: 8080}}}
}

func TestTopologyPipelineCoalescesWithoutRemovingHTTPDetails(t *testing.T) {
	at := time.Date(2026, 9, 17, 0, 0, 1, 0, time.UTC)
	exporter := &recordingTopologyExporter{}
	encoder, err := newEventOutput(io.Discard, "node", func() time.Time { return at }, topologyTestOptions(exporter))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		tx := topologyTestHTTP(at)
		tx.Flow.Source.Port += uint16(i)
		if err := encoder.Encode(tx); err != nil {
			t.Fatal(err)
		}
	}
	if len(exporter.summaries) != 0 {
		t.Fatal("summary sent before aggregation boundary")
	}
	if err := encoder.Flush(at.Truncate(time.Minute).Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	if len(exporter.http) != 100 || len(exporter.summaries) != 1 {
		t.Fatalf("raw/summary counts = %d/%d; want 100/1", len(exporter.http), len(exporter.summaries))
	}
}

func TestTopologyPipelineFinalizesL4AndDNSAndHTTP(t *testing.T) {
	at := time.Date(2026, 9, 17, 0, 0, 1, 0, time.UTC)
	exporter := &recordingTopologyExporter{}
	encoder, err := newEventOutput(io.Discard, "node", func() time.Time { return at.Add(time.Second) }, topologyTestOptions(exporter))
	if err != nil {
		t.Fatal(err)
	}
	http := topologyTestHTTP(at)
	observation := flow.Observation{ObservedAt: at, Flow: http.Flow, RTT: flow.Distribution{Count: 1, SumMicros: 1, MinMicros: 1, MaxMicros: 1}}
	observation.Flow.Direction = "connection"
	dnsRecord := dns.Transaction{SchemaVersion: dns.SchemaVersion, ObservedAt: at, NodeName: "node", Protocol: "udp",
		Client: http.Flow.Source, Server: flow.Endpoint{Address: "10.0.0.53", Port: 53}, Outcome: dns.OutcomeResponse, ResponseCode: "NOERROR", LatencyMeasured: true, LatencyMicros: 1}
	for _, record := range []any{observation, &http, &dnsRecord} {
		if err := encoder.Encode(record); err != nil {
			t.Fatal(err)
		}
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	if len(exporter.windows) != 1 || len(exporter.http) != 1 || len(exporter.dns) != 1 || len(exporter.summaries) != 3 {
		t.Fatalf("missing final observations: windows=%d http=%d dns=%d summaries=%d", len(exporter.windows), len(exporter.http), len(exporter.dns), len(exporter.summaries))
	}
}

func TestTopologySummaryIsOptInAndExporterCapabilityChecked(t *testing.T) {
	at := time.Date(2026, 9, 17, 0, 0, 1, 0, time.UTC)
	exporter := &recordingTopologyExporter{}
	options := topologyTestOptions(exporter)
	options.Topology = nil
	encoder, err := newEventOutput(io.Discard, "node", func() time.Time { return at }, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := encoder.Encode(topologyTestHTTP(at)); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	if len(exporter.http) != 1 || len(exporter.summaries) != 0 {
		t.Fatal("default export contract changed")
	}
	for _, unsupported := range []WindowExporter{nil, &recordingWindowExporter{}, &recordingTypedExporter{}} {
		encoder, err := newEventOutput(io.Discard, "node", time.Now, topologyTestOptions(unsupported))
		if err == nil {
			encoder.Close()
			t.Fatal("unsupported summary export silently accepted")
		}
	}
}

func TestTopologyFailureLatchesWithoutPublishingPartialMap(t *testing.T) {
	at := time.Date(2026, 9, 17, 0, 0, 1, 0, time.UTC)
	exporter := &recordingTopologyExporter{}
	options := topologyTestOptions(exporter)
	options.Topology.MaxEntries = 1
	encoder, err := newEventOutput(io.Discard, "node", func() time.Time { return at }, options)
	if err != nil {
		t.Fatal(err)
	}
	tx := topologyTestHTTP(at)
	if err := encoder.Encode(tx); err != nil {
		t.Fatal(err)
	}
	tx.Flow.Destination.Address = "10.0.0.3"
	if err := encoder.Encode(tx); err == nil {
		t.Fatal("summary capacity loss hidden")
	}
	tx.Flow.Destination.Address = "10.0.0.4"
	if err := encoder.Encode(tx); err == nil {
		t.Fatal("summary failure was not latched")
	}
	_ = encoder.Close()
	if len(exporter.http) != 2 || len(exporter.summaries) != 0 {
		t.Fatal("export continued after summary rejection")
	}
}

func TestTopologyExporterRejectionStopsTheSummaryBatch(t *testing.T) {
	at := time.Date(2026, 9, 17, 0, 0, 1, 0, time.UTC)
	rejected := errors.New("summary rejected")
	exporter := &recordingTopologyExporter{summaryErr: rejected}
	encoder, err := newEventOutput(io.Discard, "node", func() time.Time { return at }, topologyTestOptions(exporter))
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"10.0.0.2", "10.0.0.3"} {
		tx := topologyTestHTTP(at)
		tx.Flow.Destination.Address = address
		if err := encoder.Encode(tx); err != nil {
			t.Fatal(err)
		}
	}
	if err := encoder.Flush(at.Add(time.Minute)); !errors.Is(err, rejected) {
		t.Fatalf("rejection lost: %v", err)
	}
	_ = encoder.Close()
	if len(exporter.summaries) != 1 {
		t.Fatal("summary batch continued after rejection")
	}
}
