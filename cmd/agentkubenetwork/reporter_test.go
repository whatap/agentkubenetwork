package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/app"
	"github.com/whatap/agentkubenetwork/internal/collector"
)

func TestCLILogConfiguration(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		var output bytes.Buffer
		if err := runArgs([]string{"-log-level=" + level, "-log-interval=0"}, strings.NewReader(""), &output, nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, arg := range []string{"-log-level=", "-log-level=INFO", "-log-level=trace", "-log-interval=-1ns", "-log-interval=bad"} {
		if err := runArgs([]string{arg}, forbiddenInput{t}, io.Discard, nil); err == nil {
			t.Fatalf("accepted %s", arg)
		}
	}
}

func TestTagCountReporterLevelsFinalFailureAndJoin(t *testing.T) {
	setTagCountTestConfig(t)
	for _, level := range []string{"debug", "info", "warn", "error"} {
		for _, interval := range []time.Duration{0, 10 * time.Millisecond} {
			t.Run(level+interval.String(), func(t *testing.T) {
				var summary bytes.Buffer
				ctx, cancel := context.WithTimeout(context.Background(), 65*time.Millisecond)
				defer cancel()
				err := runTagCount(ctx, io.Discard, &summary, func(collector.OpenOptions) (collector.EventReader, error) {
					<-ctx.Done()
					return nil, io.ErrUnexpectedEOF
				}, bpfRunConfig{NodeName: "node", Events: app.EventOptions{OutputMode: "windows", WindowSize: time.Second}}, tagcountRunOptions{QueueCapacity: 4, Timeout: time.Second, DrainTimeout: time.Second, LogLevel: level, LogInterval: interval})
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("lost failure: %v", err)
				}
				data := append([]byte(nil), summary.Bytes()...)
				time.Sleep(25 * time.Millisecond)
				if !bytes.Equal(data, summary.Bytes()) {
					t.Fatal("reporter not joined")
				}
				lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
				periodic := interval > 0 && (level == "info" || level == "debug")
				if periodic {
					if len(lines) < 2 || len(lines) > 9 {
						t.Fatalf("unbounded/missing periodic: %d", len(lines))
					}
				} else if len(lines) != 1 {
					t.Fatalf("unexpected periodic: %d", len(lines))
				}
				for i, line := range lines {
					var entry struct {
						Final     bool   `json:"final"`
						RunFailed bool   `json:"run_failed"`
						Stage     string `json:"stage"`
					}
					if err := json.Unmarshal(line, &entry); err != nil {
						t.Fatal(err)
					}
					if entry.Stage != "tcp_write" || entry.Final != (i == len(lines)-1) {
						t.Fatalf("bad summary %s", line)
					}
					if entry.Final && !entry.RunFailed {
						t.Fatalf("failure missing: %s", line)
					}
					if bytes.Contains(line, []byte(io.ErrUnexpectedEOF.Error())) {
						t.Fatal("summary exposes arbitrary error text")
					}
				}
			})
		}
	}
}
