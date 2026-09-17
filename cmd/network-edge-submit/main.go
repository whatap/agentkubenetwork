// network-edge-submit reads JSONL from stdin and sends only completed windows.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/whatap/agentkubenetwork/internal/bridge"
	"github.com/whatap/agentkubenetwork/internal/flow"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }
func run(args []string, in io.Reader, out, errout io.Writer) (exitCode int) {
	fs := flag.NewFlagSet("network-edge-submit", flag.ContinueOnError)
	fs.SetOutput(errout)
	address := fs.String("address", "", "literal loopback node listener address (required)")
	timeout := fs.Duration("timeout", time.Second, "per-request deadline")
	if e := fs.Parse(args); e != nil {
		return 2
	}
	if fs.NArg() != 0 {
		return 2
	}
	client, e := bridge.NewClient(*address, *timeout)
	if e != nil {
		fmt.Fprintln(errout, e)
		return 2
	}
	summary := struct {
		Accepted   int    `json:"accepted"`
		Failed     int    `json:"failed"`
		Skipped    int    `json:"skipped"`
		Partial    int    `json:"skipped_partial"`
		Unmeasured int    `json:"skipped_unmeasured"`
		Incomplete int    `json:"skipped_incomplete_tuple"`
		Ignored    int    `json:"ignored"`
		Stage      string `json:"stage"`
	}{Stage: "node_queue"}
	defer func() {
		if e := json.NewEncoder(out).Encode(summary); e != nil {
			fmt.Fprintf(errout, "summary output failed (accepted=%d, failed=%d): %v\n", summary.Accepted, summary.Failed, e)
			if exitCode == 0 {
				exitCode = 1
			}
		}
	}()
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	line := 0
	fail := func(e error) int { summary.Failed++; fmt.Fprintf(errout, "line %d: %v\n", line, e); return 1 }
	for scanner.Scan() {
		line++
		var header struct {
			Schema string `json:"schemaVersion"`
		}
		b := scanner.Bytes()
		if !utf8.Valid(b) {
			return fail(errors.New("invalid UTF-8 JSON"))
		}
		if e := json.Unmarshal(b, &header); e != nil {
			return fail(e)
		}
		if header.Schema == "" {
			return fail(errors.New("missing schemaVersion"))
		}
		if header.Schema != flow.SchemaVersion {
			if strings.HasPrefix(header.Schema, "network.flow/") || strings.HasPrefix(header.Schema, "network.window/") {
				return fail(errors.New("unsupported window schema"))
			}
			summary.Ignored++
			continue
		}
		var w flow.Window
		if e := json.Unmarshal(b, &w); e != nil {
			return fail(e)
		}
		e := client.Send(context.Background(), w)
		switch {
		case errors.Is(e, bridge.ErrPartialWindow):
			summary.Partial++
			summary.Skipped++
		case errors.Is(e, bridge.ErrNoSamples):
			summary.Unmeasured++
			summary.Skipped++
		case errors.Is(e, bridge.ErrIncompleteTuple):
			summary.Incomplete++
			summary.Skipped++
		case e != nil:
			return fail(e)
		default:
			summary.Accepted++
		}
	}
	if e := scanner.Err(); e != nil {
		return fail(e)
	}
	return 0
}
