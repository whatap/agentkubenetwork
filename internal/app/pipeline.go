package app

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
)

// eventOutput keeps the existing raw format by default. Windows aggregates
// only L4 observations; L7/DNS transactions and coverage records remain typed
// records, never silently coerced into TCP latency or healthy empty buckets.
type eventOutput struct {
	*queuedOutput
	stream *flow.Stream
	mode   string
	node   string
}

func newEventOutput(output io.Writer, node string, now func() time.Time, options EventOptions) (*eventOutput, error) {
	mode := options.OutputMode
	if mode == "" {
		mode = "raw"
	}
	if mode != "raw" && mode != "windows" && mode != "both" {
		return nil, fmt.Errorf("unsupported output mode %q", mode)
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
	return &eventOutput{queuedOutput: queue, stream: stream, mode: mode, node: node}, nil
}

func (e *eventOutput) Encode(record any) error {
	var observation flow.Observation
	switch value := record.(type) {
	case flow.Observation:
		observation = value
	case resolvedObservation:
		observation = value.Observation
	default:
		return e.queuedOutput.Encode(record)
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

func (e *eventOutput) Flush(now time.Time) error {
	if e.stream == nil {
		return nil
	}
	for _, window := range e.stream.Flush(now) {
		if err := e.queuedOutput.Encode(window); err != nil {
			return err
		}
	}
	return nil
}

func (e *eventOutput) Close() error {
	var finalErr error
	if e.stream != nil {
		for _, window := range e.stream.Finish(e.now()) {
			if err := e.queuedOutput.Encode(window); err != nil {
				finalErr = err
				break
			}
		}
	}
	return errors.Join(finalErr, e.queuedOutput.Close())
}
