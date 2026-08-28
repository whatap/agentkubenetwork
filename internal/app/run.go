package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
)

func Run(input io.Reader, output io.Writer, windowSize time.Duration) error {
	decoder := json.NewDecoder(input)
	decoder.DisallowUnknownFields()

	observations := make([]flow.Observation, 0)
	for {
		var observation flow.Observation
		if err := decoder.Decode(&observation); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("decode observation: %w", err)
		}
		observations = append(observations, observation)
	}

	windows, err := flow.Aggregate(observations, windowSize)
	if err != nil {
		return fmt.Errorf("aggregate observations: %w", err)
	}

	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	for _, window := range windows {
		if err := encoder.Encode(window); err != nil {
			return fmt.Errorf("encode window: %w", err)
		}
	}
	return nil
}
