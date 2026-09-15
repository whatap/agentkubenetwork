package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/whatap/agentkubenetwork/internal/app"
	"github.com/whatap/agentkubenetwork/internal/collector"
	"github.com/whatap/agentkubenetwork/internal/conntrack"
	"github.com/whatap/agentkubenetwork/internal/process"
)

type bpfOpener func(collector.OpenOptions) (collector.EventReader, error)

type bpfRunConfig struct {
	NodeName         string
	MaxEvents        int
	OpenSSLLibraries []string
	ConntrackEnabled bool
	ConntrackTTL     time.Duration
	ProcessEnabled   bool
	ProcRoot         string
	Events           app.EventOptions
}

func main() {
	if err := run(); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintf(os.Stderr, "agentkubenetwork: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	return runArgs(os.Args[1:], os.Stdin, os.Stdout, func(options collector.OpenOptions) (collector.EventReader, error) { return collector.OpenBPF(options) })
}

func runArgs(args []string, input io.Reader, output io.Writer, open bpfOpener) error {
	flags := flag.NewFlagSet("agentkubenetwork", flag.ContinueOnError)
	source := flags.String("source", "stdin", "observation source: stdin (batch) or ebpf (live)")
	windowSize := flags.Duration("window", 5*time.Second, "flow aggregation window")
	outputMode := flags.String("output-mode", "raw", "live L4 output: raw, windows, or both; L7/DNS/coverage retain their typed records")
	allowedLateness := flags.Duration("allowed-lateness", time.Second, "lateness allowance before finalizing live windows")
	maxWindows := flags.Int("max-windows", 16384, "maximum active identity/windows before explicit coverage drops")
	queueCapacity := flags.Int("output-queue", 4096, "maximum queued output records; overflow is reported as telemetry loss")
	drainTimeout := flags.Duration("output-drain-timeout", 5*time.Second, "maximum shutdown wait for output delivery")
	nodeName := flags.String("node-name", os.Getenv("NODE_NAME"), "node identity for eBPF observations")
	maxEvents := flags.Int("max-events", 0, "stop after N eBPF events; zero runs continuously")
	duration := flags.Duration("duration", 0, "stop live capture gracefully after this duration; zero runs until signal")
	opensslLibrary := flags.String("openssl-library", "", "comma-separated libssl paths for OpenSSL plaintext uprobes")
	conntrackEnabled := flags.Bool("conntrack", true, "resolve NAT-translated destinations via kernel conntrack")
	conntrackTTL := flags.Duration("conntrack-ttl", time.Second, "minimum interval between conntrack table dumps")
	processEnabled := flags.Bool("process", true, "resolve socket observer PID/container identity via procfs (raw mode can include cmdline)")
	procRoot := flags.String("proc-root", "/proc", "procfs root for process resolution")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}

	switch *source {
	case "stdin":
		return app.Run(input, output, *windowSize)
	case "ebpf":
		if *duration < 0 {
			return errors.New("duration must not be negative")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if *duration > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, *duration)
			defer cancel()
		}
		if *nodeName == "" {
			hostname, err := os.Hostname()
			if err != nil {
				return fmt.Errorf("resolve node name: %w", err)
			}
			*nodeName = hostname
		}
		config := bpfRunConfig{NodeName: *nodeName, MaxEvents: *maxEvents, OpenSSLLibraries: splitNonEmpty(*opensslLibrary), ConntrackEnabled: *conntrackEnabled, ConntrackTTL: *conntrackTTL, ProcessEnabled: *processEnabled, ProcRoot: *procRoot,
			Events: app.EventOptions{OutputMode: *outputMode, WindowSize: *windowSize, AllowedLateness: *allowedLateness, MaxWindows: *maxWindows, OutputQueueCapacity: *queueCapacity, OutputDrainTimeout: *drainTimeout}}
		if config.MaxEvents < 0 || config.Events.WindowSize <= 0 || config.Events.AllowedLateness < 0 || config.Events.MaxWindows <= 0 || config.Events.OutputQueueCapacity <= 0 || config.Events.OutputDrainTimeout <= 0 {
			return errors.New("invalid live limits: window, max-windows, output-queue and drain timeout must be positive; max-events and allowed-lateness must be nonnegative")
		}
		if config.Events.OutputMode != "raw" && config.Events.OutputMode != "windows" && config.Events.OutputMode != "both" {
			return fmt.Errorf("unsupported output mode %q", config.Events.OutputMode)
		}
		return runBPF(ctx, output, open, config)
	default:
		return fmt.Errorf("unsupported source %q", *source)
	}
}

func runBPF(ctx context.Context, output io.Writer, open bpfOpener, config bpfRunConfig) (err error) {
	reader, err := open(collector.OpenOptions{OpenSSLLibraries: config.OpenSSLLibraries})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, reader.Close()) }()
	var resolver app.DestinationResolver
	if config.ConntrackEnabled {
		resolver = conntrack.NewNetlinkResolver(config.ConntrackTTL)
	}
	var processes app.ProcessResolver
	if config.ProcessEnabled {
		processes = process.NewResolver(config.ProcRoot)
	}
	return app.RunEventsWithOptions(ctx, reader, output, config.NodeName, config.MaxEvents, time.Now, resolver, processes, config.Events)
}

func splitNonEmpty(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
