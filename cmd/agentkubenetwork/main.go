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
	"github.com/whatap/agentkubenetwork/internal/podidentity"
	"github.com/whatap/agentkubenetwork/internal/process"
	"github.com/whatap/agentkubenetwork/internal/topology"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type bpfOpener func(collector.OpenOptions) (collector.EventReader, error)

type bpfRunConfig struct {
	PodIdentity      bool
	Kubeconfig       string
	PodSyncTimeout   time.Duration
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
	drainTimeout := flags.Duration("output-drain-timeout", 5*time.Second, "maximum shutdown wait for output delivery, including topology summaries waiting for the TagCount queue")
	exportMode := flags.String("export", "none", "optional backend export: none or tagcount (live windows/both only)")
	stdout := flags.String("stdout", "auto", "telemetry stdout: auto (none with tagcount, otherwise jsonl), jsonl, or none; overrides WHATAP_STDOUT")
	logLevel := flags.String("log-level", "info", "operational log level: debug, info, warn, or error (never enables telemetry stdout); overrides WHATAP_LOG_LEVEL")
	logInterval := flags.Duration("log-interval", time.Minute, "TagCount summary interval; zero disables periodic summaries, not final summaries; overrides WHATAP_LOG_INTERVAL")
	whatapConfig := flags.String("whatap-config", "", "optional whatap properties file; WHATAP_ACCESSKEY and WHATAP_SERVER_HOST environment variables take precedence")
	tagcountQueue := flags.Int("tagcount-queue", 1024, "maximum queued TagCount records (1..16384); detailed overflow is counted, topology summaries wait for room")
	tagcountTimeout := flags.Duration("tagcount-timeout", 5*time.Second, "whole TagCount connect/handshake/write deadline")
	tagcountDrain := flags.Duration("tagcount-drain-timeout", 5*time.Second, "maximum shutdown wait for TagCount writes")
	nodeName := flags.String("node-name", os.Getenv("NODE_NAME"), "node identity for eBPF observations")
	maxEvents := flags.Int("max-events", 0, "stop after N eBPF events; zero runs continuously")
	duration := flags.Duration("duration", 0, "stop live capture gracefully after this duration; zero runs until signal")
	opensslLibrary := flags.String("openssl-library", "", "comma-separated libssl/libcrypto paths for complete OpenSSL SSL/BIO plaintext uprobes")
	conntrackEnabled := flags.Bool("conntrack", true, "resolve NAT-translated destinations via kernel conntrack")
	conntrackTTL := flags.Duration("conntrack-ttl", time.Second, "minimum interval between conntrack table dumps")
	processEnabled := flags.Bool("process", true, "resolve socket observer PID/container identity via procfs (raw mode can include cmdline)")
	procRoot := flags.String("proc-root", "/proc", "procfs root for process resolution")
	podIdentity := flags.Bool("pod-identity", true, "enrich live observations with Pod UIDs using one read-only Pod informer (ebpf only; disable with -pod-identity=false)")
	kubeconfig := flags.String("kubeconfig", "", "explicit kubeconfig for Pod identity; empty uses in-cluster configuration only")
	podSyncTimeout := flags.Duration("pod-sync-timeout", 10*time.Second, "Pod informer startup sync and shutdown bound")
	topologySummary := flags.Bool("topology-summary", false, "opt in to workload relationship TagCount summaries and read-only ReplicaSet/Job informers; overrides WHATAP_TOPOLOGY_SUMMARY")
	topologyCluster := flags.String("topology-cluster-id", "", "cluster name shared by all observers; defaults to the access key's project code (one WhaTap Kubernetes project monitors one cluster); overrides WHATAP_TOPOLOGY_CLUSTER_ID")
	topologyWindow := flags.Duration("topology-window", time.Minute, "relationship summary window; does not change the raw flow window; overrides WHATAP_TOPOLOGY_WINDOW")
	topologyMaxEntries := flags.Int("topology-max-entries", 4096, "maximum active relationship/window entries, and of summaries waiting for the TagCount queue (1..65536); exceeding either fails explicitly; overrides WHATAP_TOPOLOGY_MAX_ENTRIES")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}
	if err := applyLoggingEnvironment(flags); err != nil {
		return err
	}
	if err := applyTopologyEnvironment(flags); err != nil {
		return err
	}
	if err := validateLogging(*logLevel, *logInterval); err != nil {
		return err
	}
	var podIdentitySet, podSyncTimeoutSet, topologyOptionsSet, topologyClusterSet bool
	flags.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "pod-identity":
			podIdentitySet = true
		case "pod-sync-timeout":
			podSyncTimeoutSet = true
		case "topology-cluster-id":
			topologyClusterSet = true
			topologyOptionsSet = true
		case "topology-window", "topology-max-entries":
			topologyOptionsSet = true
		}
	})
	if !podIdentitySet && *source != "ebpf" {
		*podIdentity = false
	}
	var topologyConfig *topology.Config
	if *topologySummary {
		if *source != "ebpf" {
			return errors.New("topology summary requires -source=ebpf")
		}
		if *exportMode != "tagcount" {
			return errors.New("topology summary requires -export=tagcount")
		}
		if !*podIdentity {
			return errors.New("topology summary requires -pod-identity")
		}
		// Unset means the project code, filled in once the access key is parsed.
		// A value that was given, including an empty one, must be a valid name.
		if topologyClusterSet {
			if len(*topologyCluster) == 0 || len(*topologyCluster) > 253 {
				return errors.New("topology-cluster-id must contain 1..253 printable non-whitespace ASCII bytes")
			}
			for _, c := range *topologyCluster {
				if c < 33 || c > 126 {
					return errors.New("topology-cluster-id must contain 1..253 printable non-whitespace ASCII bytes")
				}
			}
		}
		if *topologyWindow < time.Millisecond || *topologyWindow > time.Minute || *topologyWindow%time.Millisecond != 0 || *windowSize <= 0 || *topologyWindow%*windowSize != 0 {
			return errors.New("topology window must be whole milliseconds in 1ms..60s and a multiple of the flow window")
		}
		if *topologyMaxEntries < 1 || *topologyMaxEntries > 65536 {
			return errors.New("topology max entries must be between 1 and 65536")
		}
		topologyConfig = &topology.Config{ClusterID: *topologyCluster, WindowSize: *topologyWindow, MaxEntries: *topologyMaxEntries}
	} else if topologyOptionsSet {
		return errors.New("topology configuration requires -topology-summary")
	}
	if *exportMode != "none" && *exportMode != "tagcount" {
		return fmt.Errorf("unsupported backend export %q", *exportMode)
	}
	switch *stdout {
	case "auto":
		if *exportMode == "tagcount" {
			output = io.Discard
		}
	case "jsonl":
	case "none":
		if *exportMode != "tagcount" {
			return errors.New("-stdout=none requires -export=tagcount")
		}
		output = io.Discard
	default:
		return errors.New("stdout must be auto, jsonl, or none")
	}
	if *exportMode == "tagcount" && *source != "ebpf" {
		return errors.New("direct TagCount export requires -source=ebpf; stdin remains a batch-only diagnostic path")
	}

	if podSyncTimeoutSet && *source != "ebpf" {
		return errors.New("-pod-sync-timeout requires -source=ebpf")
	}
	if *podIdentity && (*source != "ebpf" || *podSyncTimeout <= 0) {
		return errors.New("pod identity requires -source=ebpf and positive -pod-sync-timeout")
	}
	if *kubeconfig != "" && !*podIdentity {
		return errors.New("-kubeconfig requires -pod-identity")
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
			PodIdentity: *podIdentity, Kubeconfig: *kubeconfig, PodSyncTimeout: *podSyncTimeout,
			Events: app.EventOptions{OutputMode: *outputMode, WindowSize: *windowSize, AllowedLateness: *allowedLateness, MaxWindows: *maxWindows, OutputQueueCapacity: *queueCapacity, OutputDrainTimeout: *drainTimeout, Topology: topologyConfig}}
		if config.MaxEvents < 0 || config.Events.WindowSize <= 0 || config.Events.AllowedLateness < 0 || config.Events.MaxWindows <= 0 || config.Events.OutputQueueCapacity <= 0 || config.Events.OutputDrainTimeout <= 0 {
			return errors.New("invalid live limits: window, max-windows, output-queue and drain timeout must be positive; max-events and allowed-lateness must be nonnegative")
		}
		if config.Events.OutputMode != "raw" && config.Events.OutputMode != "windows" && config.Events.OutputMode != "both" {
			return fmt.Errorf("unsupported output mode %q", config.Events.OutputMode)
		}
		if *exportMode == "tagcount" {
			return runTagCount(ctx, output, os.Stderr, open, config, tagcountRunOptions{ConfigPath: *whatapConfig, QueueCapacity: *tagcountQueue, Timeout: *tagcountTimeout, DrainTimeout: *tagcountDrain, LogLevel: *logLevel, LogInterval: *logInterval})
		}
		return runBPF(ctx, output, open, config)
	default:
		return fmt.Errorf("unsupported source %q", *source)
	}
}

func runBPF(ctx context.Context, output io.Writer, open bpfOpener, config bpfRunConfig) (err error) {
	if config.PodIdentity {
		var kube *rest.Config
		if config.Kubeconfig != "" {
			kube, err = clientcmd.BuildConfigFromFlags("", config.Kubeconfig)
		} else {
			kube, err = rest.InClusterConfig()
		}
		if err != nil {
			return fmt.Errorf("pod identity configuration: %w", err)
		}
		startPods := podidentity.Start
		if config.Events.Topology != nil {
			startPods = podidentity.StartWithWorkloads
		}
		pods, stop, startErr := startPods(ctx, kube, config.PodSyncTimeout)
		if startErr != nil {
			return startErr
		}
		defer func() { err = errors.Join(err, stop()) }()
		config.Events.PodEnricher = pods
	}
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
