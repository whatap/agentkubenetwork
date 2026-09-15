package flow

import (
	"errors"
	"time"
)

// ErrLateObservation means the observation belongs to a finalized bucket.
var ErrLateObservation = errors.New("observation window is already finalized")

var ErrWindowCapacity = errors.New("active window capacity reached")

var ErrStreamClosed = errors.New("window stream is finished")

type StreamConfig struct {
	WindowSize      time.Duration
	AllowedLateness time.Duration
	MaxWindows      int
}

type Stream struct {
	config       StreamConfig
	windows      map[aggregateKey]*Window
	watermark    time.Time
	hasWatermark bool
	finished     bool
}

func NewStream(config StreamConfig) (*Stream, error) {
	if config.WindowSize <= 0 {
		return nil, errors.New("window size must be positive")
	}
	if config.AllowedLateness < 0 {
		return nil, errors.New("allowed lateness must be nonnegative")
	}
	if config.MaxWindows < 0 {
		return nil, errors.New("max windows must be nonnegative")
	}
	if config.MaxWindows == 0 {
		config.MaxWindows = 16384
	}
	return &Stream{config: config, windows: make(map[aggregateKey]*Window)}, nil
}

func (s *Stream) Add(observation Observation) error {
	if s.finished {
		return ErrStreamClosed
	}
	if observation.ObservedAt.IsZero() {
		return errors.New("observation time is required")
	}
	key := keyFor(observation, s.config.WindowSize)
	if s.hasWatermark && !key.Start.Add(s.config.WindowSize).After(s.watermark) {
		return ErrLateObservation
	}
	window := s.windows[key]
	if window == nil {
		if len(s.windows) >= s.config.MaxWindows {
			return ErrWindowCapacity
		}
		window = key.newWindow(s.config.WindowSize)
		s.windows[key] = window
	}
	window.add(observation)
	return nil
}

func (s *Stream) Flush(now time.Time) []Window {
	watermark := now.UTC().Add(-s.config.AllowedLateness)
	if !s.hasWatermark || watermark.After(s.watermark) {
		s.watermark = watermark
		s.hasWatermark = true
	}
	var windows []Window
	for key, window := range s.windows {
		if !window.WindowEnd.After(s.watermark) {
			windows = append(windows, *window)
			delete(s.windows, key)
		}
	}
	sortWindows(windows)
	return windows
}

// Finish is terminal. Windows not yet finalized by the normal lateness
// watermark are explicitly partial; shutdown never invents a full interval.
func (s *Stream) Finish(now time.Time) []Window {
	if s.finished {
		return nil
	}
	windows := s.Flush(now)
	for key, window := range s.windows {
		window.Partial = true
		windows = append(windows, *window)
		delete(s.windows, key)
	}
	s.finished = true
	sortWindows(windows)
	return windows
}

func (s *Stream) Len() int { return len(s.windows) }
