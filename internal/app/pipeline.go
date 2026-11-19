package app

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/whatap/agentkubenetwork/internal/dns"
	"github.com/whatap/agentkubenetwork/internal/flow"
	"github.com/whatap/agentkubenetwork/internal/l7"
	"github.com/whatap/agentkubenetwork/internal/topology"
)

// eventOutput keeps the existing raw format by default. Windows aggregates
// only L4 observations; L7/DNS transactions and coverage records remain typed
// records, never silently coerced into TCP latency or healthy empty buckets.
type eventOutput struct {
	pods interface{ Enrich(*flow.Observation) }
	*queuedOutput
	stream          *flow.Stream
	mode            string
	node            string
	captureTime     func() time.Time
	exporter        WindowExporter
	exportLost      uint64
	exportFailure   error
	topology        *topology.Aggregator
	allowedLateness time.Duration
	// Summaries of closed windows that the exporter had no room for, in export
	// order. They are offered again on every flush; topologyLimit bounds them.
	topologyBacklog []topology.Summary
	topologyLimit   int
	// topologyBurst bounds the summaries queued in one flush; zero is no bound.
	topologyBurst int
}

func newEventOutput(output io.Writer, node string, now func() time.Time, options EventOptions) (*eventOutput, error) {
	mode := options.OutputMode
	if mode == "" {
		mode = "raw"
	}
	if mode != "raw" && mode != "windows" && mode != "both" {
		return nil, fmt.Errorf("unsupported output mode %q", mode)
	}
	if options.WindowExporter != nil && mode == "raw" {
		return nil, errors.New("window export requires windows or both output mode")
	}
	var stream *flow.Stream
	if mode != "raw" {
		window := options.WindowSize
		if window == 0 {
			window = 5 * time.Second
		}
		var err error
		stream, err = flow.NewStream(flow.StreamConfig{WindowSize: window, AllowedLateness: options.AllowedLateness, MaxWindows: options.MaxWindows})
		if err != nil {
			return nil, err
		}
	}
	var relationships *topology.Aggregator
	topologyLimit, topologyBurst := 0, 0
	if options.Topology != nil {
		if _, ok := options.WindowExporter.(TopologyExporter); !ok {
			return nil, errors.New("topology summary requires a topology-capable window exporter")
		}
		if _, ok := options.WindowExporter.(TypedEventExporter); !ok {
			return nil, errors.New("topology summary requires typed HTTP/DNS export")
		}
		window := options.WindowSize
		if window == 0 {
			window = 5 * time.Second
		}
		if options.Topology.WindowSize < window || options.Topology.WindowSize%window != 0 {
			return nil, errors.New("topology window must be a multiple of the flow window")
		}
		var err error
		relationships, err = topology.New(*options.Topology)
		if err != nil {
			return nil, err
		}
		topologyLimit = options.Topology.MaxEntries
		if burster, ok := options.WindowExporter.(topologyBurster); ok {
			topologyBurst = burster.TopologyBurst()
		}
		// One flush per collection tick queues at most one share. If a window's
		// ticks cannot hand over the entry bound, the summaries would pile up
		// and stop the run later; refuse the configuration now instead.
		if ticks := int64(options.Topology.WindowSize / resolutionRetryInterval); topologyBurst > 0 && ticks*int64(topologyBurst) < int64(topologyLimit) {
			return nil, fmt.Errorf("topology summary: the export queue is too small: one flush queues at most %d summaries, so the %d flushes of a %s window cannot hand over %d entries; raise the TagCount queue or lower the topology entry bound", topologyBurst, ticks, options.Topology.WindowSize, topologyLimit)
		}
	}
	queue, err := newQueuedOutput(output, node, now, options.OutputQueueCapacity, options.OutputDrainTimeout)
	if err != nil {
		return nil, err
	}
	return &eventOutput{queuedOutput: queue, stream: stream, mode: mode, node: node, captureTime: now, exporter: options.WindowExporter, pods: options.PodEnricher,
		topology: relationships, allowedLateness: options.AllowedLateness, topologyLimit: topologyLimit, topologyBurst: topologyBurst}, nil
}

func (e *eventOutput) Encode(record any) error {
	var observation flow.Observation
	switch value := record.(type) {
	case flow.Observation:
		observation = value
	case resolvedObservation:
		observation = value.Observation
	default:
		// Preserve JSONL evidence before validating or queuing backend export.
		if err := e.queuedOutput.Encode(record); err != nil {
			return err
		}
		return e.exportTyped(record)
	}
	if e.pods != nil {
		e.pods.Enrich(&observation)
		switch value := record.(type) {
		case resolvedObservation:
			value.Observation = observation
			record = value
		default:
			record = observation
		}
	}
	if e.stream != nil {
		if err := e.stream.Add(observation); err != nil {
			reason := ""
			switch {
			case errors.Is(err, flow.ErrLateObservation):
				reason = "late_observation"
			case errors.Is(err, flow.ErrWindowCapacity):
				reason = "window_capacity"
			default:
				return err
			}
			drop := struct {
				SchemaVersion   string       `json:"schemaVersion"`
				ObservedAt      time.Time    `json:"observedAt"`
				ObservationTime time.Time    `json:"observationTime"`
				Flow            flow.FlowKey `json:"flow"`
				Reason          string       `json:"reason"`
			}{"network.aggregation.drop/v1alpha1", e.now(), observation.ObservedAt, observation.Flow, reason}
			if err := e.queuedOutput.Encode(drop); err != nil {
				return err
			}
		}
	}
	if e.mode != "windows" {
		return e.queuedOutput.Encode(record)
	}
	return nil
}

func (e *eventOutput) exportTyped(record any) (err error) {
	if e.exportFailure != nil {
		return e.exportFailure
	}
	defer func() {
		if err != nil {
			e.exportFailure = err
		}
	}()
	exporter, ok := e.exporter.(TypedEventExporter)
	if !ok {
		return nil
	}
	switch value := record.(type) {
	case l7.Transaction:
		err = exporter.ExportL7(value)
	case *l7.Transaction:
		if value == nil {
			return errors.New("nil HTTP transaction")
		}
		err = exporter.ExportL7(*value)
	case dns.Transaction:
		err = exporter.ExportDNS(value)
	case *dns.Transaction:
		if value == nil {
			return errors.New("nil DNS transaction")
		}
		err = exporter.ExportDNS(*value)
	case l7.Drop:
		return exporter.ExportL7Drop(value)
	case *l7.Drop:
		if value == nil {
			return errors.New("nil L7 coverage record")
		}
		return exporter.ExportL7Drop(*value)
	}
	if err != nil {
		return err
	}
	return e.observeTopology(record)
}

func (e *eventOutput) Flush(now time.Time) error {
	if e.stream == nil {
		return nil
	}
	windowErr := e.encodeWindows(e.stream.Flush(now))
	var summaryErr error
	if e.topology != nil && e.exportFailure == nil {
		summaryErr = e.exportTopology(e.topology.FlushBefore(now.Add(-e.allowedLateness)), false)
	}
	return errors.Join(windowErr, summaryErr, e.reportExportLoss())
}

func (e *eventOutput) encodeWindows(windows []flow.Window) error {
	var exportErr error
	for _, window := range windows {
		// Flush/Finish already removed this entire batch from the stream. Keep
		// its JSONL evidence even when export rejects an earlier window.
		if err := e.queuedOutput.Encode(window); err != nil {
			return errors.Join(exportErr, err)
		}
		// Fail closed: do not export more of this batch after rejection.
		if e.exportFailure == nil && e.exporter != nil {
			if err := e.exporter.Export(window); err != nil {
				exportErr = fmt.Errorf("export flow window: %w", err)
				e.exportFailure = exportErr
			}
		}
		// The detail exporter already accounts for incomplete tuple skips.
		// Diagnostic windows with an unbound port cannot establish a map edge.
		if e.topology != nil && e.exportFailure == nil && window.Flow.Source.Port != 0 && window.Flow.Destination.Port != 0 {
			if err := e.topology.ObserveWindow(window); err != nil {
				exportErr = fmt.Errorf("aggregate topology window: %w", err)
				e.exportFailure = exportErr
			}
		}
	}
	return exportErr
}

func (e *eventOutput) reportExportLoss() error {
	if e.exporter == nil {
		return nil
	}
	total := e.exporter.Dropped()
	if total == e.exportLost {
		return nil
	}
	drop := struct {
		SchemaVersion       string    `json:"schemaVersion"`
		ObservedAt          time.Time `json:"observedAt"`
		NodeName            string    `json:"nodeName"`
		Reason              string    `json:"reason"`
		DroppedRecords      uint64    `json:"droppedRecords"`
		TotalDroppedRecords uint64    `json:"totalDroppedRecords"`
	}{"network.tagcount.drop/v1alpha1", e.now(), e.node, "tagcount_queue_full", total - e.exportLost, total}
	e.exportLost = total
	return e.queuedOutput.Encode(drop)
}

func (e *eventOutput) Close() error {
	var finalErr error
	if e.stream != nil {
		finalErr = e.encodeWindows(e.stream.Finish(e.captureTime()))
	}
	if e.topology != nil && e.exportFailure == nil {
		finalErr = errors.Join(finalErr, e.exportTopology(e.topology.FlushAll(), true))
	}
	if e.topology != nil && e.exportFailure == nil {
		finalErr = errors.Join(finalErr, e.drainTopologyBacklog())
	}
	if e.topology != nil && e.exportFailure != nil {
		finalErr = errors.Join(finalErr, e.topologyLeftBehind())
	}
	return errors.Join(finalErr, e.reportExportLoss(), e.queuedOutput.Close())
}
