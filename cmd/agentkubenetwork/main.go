package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/whatap/agentkubenetwork/internal/app"
	"github.com/whatap/agentkubenetwork/internal/collector"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "agentkubenetwork: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	source := flag.String("source", "stdin", "observation source: stdin or ebpf")
	windowSize := flag.Duration("window", 5*time.Second, "flow aggregation window")
	nodeName := flag.String("node-name", os.Getenv("NODE_NAME"), "node identity for eBPF observations")
	maxEvents := flag.Int("max-events", 0, "stop after N eBPF events; zero runs continuously")
	opensslLibrary := flag.String("openssl-library", "", "comma-separated libssl paths for OpenSSL plaintext uprobes")
	flag.Parse()

	switch *source {
	case "stdin":
		return app.Run(os.Stdin, os.Stdout, *windowSize)
	case "ebpf":
		if *nodeName == "" {
			hostname, err := os.Hostname()
			if err != nil {
				return fmt.Errorf("resolve node name: %w", err)
			}
			*nodeName = hostname
		}
		return runBPF(*nodeName, *maxEvents, splitNonEmpty(*opensslLibrary))
	default:
		return fmt.Errorf("unsupported source %q", *source)
	}
}

func runBPF(nodeName string, maxEvents int, opensslLibraries []string) (err error) {
	reader, err := collector.OpenBPF(collector.OpenOptions{OpenSSLLibraries: opensslLibraries})
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, reader.Close())
	}()
	return app.RunEvents(reader, os.Stdout, nodeName, maxEvents, time.Now)
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
