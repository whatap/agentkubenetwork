package main

import (
	"context"

	"errors"
	"fmt"
	"io"
	"time"

	"github.com/whatap/agentkubenetwork/internal/tagcount"
	"github.com/whatap/agentkubenetwork/internal/whatap"
)

type tagcountRunOptions struct {
	ConfigPath    string
	QueueCapacity int
	Timeout       time.Duration
	DrainTimeout  time.Duration
	LogLevel      string
	LogInterval   time.Duration
}

func runTagCount(ctx context.Context, output, diagnostics io.Writer, open bpfOpener, config bpfRunConfig, options tagcountRunOptions) (retErr error) {
	if config.Events.OutputMode != "windows" && config.Events.OutputMode != "both" {
		return errors.New("direct TagCount export requires -output-mode=windows or both")
	}
	if config.Events.WindowSize < time.Millisecond || config.Events.WindowSize > time.Minute || config.Events.WindowSize%time.Millisecond != 0 {
		return errors.New("TagCount window must be a whole number of milliseconds between 1ms and 60s")
	}
	if options.QueueCapacity < 1 || options.QueueCapacity > tagcount.MaxQueueCapacity || options.Timeout <= 0 || options.DrainTimeout <= 0 {
		return fmt.Errorf("tagcount queue must be between 1 and %d; request and drain timeouts must be positive", tagcount.MaxQueueCapacity)
	}
	if diagnostics == nil {
		return errors.New("tagcount diagnostics writer is required")
	}
	if options.LogLevel == "" {
		options.LogLevel = "info"
	}
	if err := validateLogging(options.LogLevel, options.LogInterval); err != nil {
		return err
	}
	var exporter *tagcount.Exporter
	stopReporter := func() error { return nil }
	defer func() {
		retErr = finalizeTagCount(exporter, stopReporter, diagnostics, retErr)
	}()
	transport, err := tagcount.LoadConfig(options.ConfigPath, config.NodeName, options.Timeout)
	if err != nil {
		return err
	}
	sender, err := whatap.NewClient(transport)
	if err != nil {
		return fmt.Errorf("configure direct TagCount transport: %w", err)
	}
	exporter, err = tagcount.NewExporter(sender, tagcount.ExporterConfig{NodeName: config.NodeName, QueueCapacity: options.QueueCapacity, DrainTimeout: options.DrainTimeout})
	if err != nil {
		return errors.Join(err, sender.Close())
	}
	stopReporter = startTagCountReporter(ctx, diagnostics, exporter.Snapshot, options.LogLevel, options.LogInterval)
	config.Events.WindowExporter = exporter
	return runBPF(ctx, output, open, config)
}

func finalizeTagCount(exporter *tagcount.Exporter, stopReporter func() error, diagnostics io.Writer, retErr error) error {
	// Drain and close the transport even if a periodic diagnostics write is
	// blocked. Joining that writer must not delay exporter cleanup.
	summary := tagcount.Summary{SchemaVersion: "network.tagcount.summary/v1alpha1", Stage: "tcp_write"}
	if exporter != nil {
		retErr = errors.Join(retErr, exporter.Close())
		summary = exporter.Snapshot()
	}
	// Still join before final diagnostics: the writer may be a plain buffer,
	// and the returned error must include any periodic write failure.
	retErr = errors.Join(retErr, stopReporter())
	return errors.Join(retErr, writeTagCountSummary(diagnostics, summary, true, retErr != nil))
}
