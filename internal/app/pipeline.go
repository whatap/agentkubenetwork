package app

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/whatap/agentkubenetwork/internal/dns"
	"github.com/whatap/agentkubenetwork/internal/flow"
	"github.com/whatap/agentkubenetwork/internal/l7"
)

// eventOutput keeps the existing raw format by default. Windows aggregates
// only L4 observations; L7/DNS transactions and coverage records remain typed
// records, never silently coerced into TCP latency or healthy empty buckets.
type eventOutput struct {
	pods interface{ Enrich(*flow.Observation) }
	*queuedOutput
	stream        *flow.Stream
	mode          string
	node          string
	captureTime   func() time.Time
	exporter      WindowExporter
	exportLost    uint64
	exportFailure error
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
	queue, err := newQueuedOutput(output, node, now, options.OutputQueueCapacity, options.OutputDrainTimeout)
	if err != nil {
		return nil, err
	}
	return &eventOutput{queuedOutput: queue, stream: stream, mode: mode, node: node, captureTime: now, exporter: options.WindowExporter, pods: options.PodEnricher}, nil
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
		return exporter.ExportL7(value)
	case *l7.Transaction:
		if value == nil {
			return errors.New("nil HTTP transaction")
		}
		return exporter.ExportL7(*value)
	case dns.Transaction:
		return exporter.ExportDNS(value)
	case *dns.Transaction:
		if value == nil {
			return errors.New("nil DNS transaction")
		}
		return exporter.ExportDNS(*value)
	case l7.Drop:
		return exporter.ExportL7Drop(value)
	case *l7.Drop:
		if value == nil {
			return errors.New("nil L7 coverage record")
		}
		return exporter.ExportL7Drop(*value)
	}
	return nil
}

func (e *eventOutput) Flush(now time.Time) error {
	if e.stream == nil {
		return nil
	}
	return errors.Join(e.encodeWindows(e.stream.Flush(now)), e.reportExportLoss())
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
	return errors.Join(finalErr, e.reportExportLoss(), e.queuedOutput.Close())
}
