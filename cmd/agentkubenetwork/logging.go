package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/whatap/agentkubenetwork/internal/tagcount"
)

func validateLogging(level string, interval time.Duration) error {
	switch level {
	case "debug", "info", "warn", "error":
	default:
		return errors.New("log-level must be debug, info, warn, or error")
	}
	if interval < 0 {
		return errors.New("log-interval must not be negative")
	}
	return nil
}

// Summaries expose only aggregate counters and status, never record bodies,
// configuration, query strings, command lines, or arbitrary error messages.
func writeTagCountSummary(w io.Writer, snapshot tagcount.Summary, final, failed bool) error {
	entry := struct {
		tagcount.Summary
		Final     bool `json:"final"`
		RunFailed bool `json:"run_failed"`
	}{snapshot, final, failed}
	if err := json.NewEncoder(w).Encode(entry); err != nil {
		return fmt.Errorf("write TagCount summary: %w", err)
	}
	return nil
}

// The returned stop cancels and joins the only periodic writer. Its caller must
// call stop before writing final diagnostics or reporting a fatal error.
func startTagCountReporter(parent context.Context, w io.Writer, snapshot func() tagcount.Summary, level string, interval time.Duration) func() error {
	if interval == 0 || (level != "info" && level != "debug") {
		return func() error { return nil }
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	var reportErr error // read only after the done-channel join
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if ctx.Err() != nil {
					return
				}
				if err := writeTagCountSummary(w, snapshot(), false, false); err != nil {
					reportErr = err
					return
				}
			}
		}
	}()
	return func() error { cancel(); <-done; return reportErr }
}
