package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/whatap/agentkubenetwork/internal/collector"
	"github.com/whatap/agentkubenetwork/internal/l7"
)

func RunEvents(reader collector.EventReader, output io.Writer, nodeName string, maxEvents int, now func() time.Time) error {
	if maxEvents < 0 {
		return errors.New("max events must not be negative")
	}
	if now == nil {
		return errors.New("wall clock is required")
	}

	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	correlator := l7.NewCorrelator(l7.Config{})
	for count := 0; maxEvents == 0 || count < maxEvents; count++ {
		event, err := reader.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read BPF event: %w", err)
		}
		observedAt := now()
		if event.Kind == collector.EventKindL7CoverageDrop {
			drop, err := event.L7CoverageDrop(nodeName, observedAt)
			if err != nil {
				return fmt.Errorf("convert L7 coverage drop: %w", err)
			}
			if err := encoder.Encode(drop); err != nil {
				return fmt.Errorf("encode L7 coverage drop: %w", err)
			}
			continue
		}
		if event.Kind == collector.EventKindL7Fragment {
			fragment, err := event.L7Fragment(nodeName, observedAt)
			if err != nil {
				return fmt.Errorf("convert BPF L7 event: %w", err)
			}
			for _, result := range correlator.Process(fragment) {
				if result.Transaction != nil {
					if err := encoder.Encode(result.Transaction); err != nil {
						return fmt.Errorf("encode L7 transaction: %w", err)
					}
				}
				if result.Drop != nil {
					if err := encoder.Encode(result.Drop); err != nil {
						return fmt.Errorf("encode L7 coverage drop: %w", err)
					}
				}
			}
			continue
		}
		observation, err := event.Observation(nodeName, observedAt)
		if err != nil {
			return fmt.Errorf("convert BPF event: %w", err)
		}
		if err := encoder.Encode(observation); err != nil {
			return fmt.Errorf("encode BPF observation: %w", err)
		}
	}
	return nil
}
