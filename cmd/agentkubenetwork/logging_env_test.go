package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/collector"
)

func clearLoggingEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{"WHATAP_STDOUT", "WHATAP_LOG_LEVEL", "WHATAP_LOG_INTERVAL"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCLIStdoutEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name     string
		stdout   string
		args     []string
		wantJSON bool
	}{
		{name: "env jsonl", stdout: "jsonl", wantJSON: true},
		{name: "env none with debug", stdout: "none"},
		{name: "env auto with debug", stdout: "auto"},
		{name: "explicit default wins", stdout: "jsonl", args: []string{"-stdout=auto"}},
		{name: "explicit jsonl wins", stdout: "none", args: []string{"-stdout=jsonl"}, wantJSON: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearLoggingEnvironment(t)
			setTagCountTestConfig(t)
			t.Setenv("WHATAP_STDOUT", tc.stdout)
			t.Setenv("WHATAP_LOG_LEVEL", "debug")
			t.Setenv("WHATAP_LOG_INTERVAL", "0")
			reader := &cliEventReader{}
			var output bytes.Buffer
			args := append([]string{"-source=ebpf", "-pod-identity=false", "-conntrack=false", "-process=false", "-output-mode=windows", "-export=tagcount"}, tc.args...)
			err := runArgs(args, strings.NewReader(""), &output, func(collector.OpenOptions) (collector.EventReader, error) {
				return reader, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(output.String(), `"partial":true`) != tc.wantJSON || (!tc.wantJSON && output.Len() != 0) || !reader.closed {
				t.Fatalf("incorrect stdout selection or reader cleanup: jsonl=%v bytes=%d closed=%v", tc.wantJSON, output.Len(), reader.closed)
			}
		})
	}
}

func TestLoggingEnvironmentPreservesOnlySinkGuard(t *testing.T) {
	clearLoggingEnvironment(t)
	t.Setenv("WHATAP_STDOUT", "none")
	input := &loggingEnvInput{}
	err := runArgs(nil, input, io.Discard, nil)
	if err == nil || !strings.Contains(err.Error(), "requires -export=tagcount") || input.read {
		t.Fatalf("environment disabled the only sink: err=%v stdin_read=%v", err, input.read)
	}
}

func TestLoggingEnvironmentDoesNotReplaceInvalidCLI(t *testing.T) {
	for _, arg := range []string{"-stdout=bad", "-log-level=", "-log-interval=-1s"} {
		t.Run(arg, func(t *testing.T) {
			clearLoggingEnvironment(t)
			t.Setenv("WHATAP_STDOUT", "jsonl")
			t.Setenv("WHATAP_LOG_LEVEL", "info")
			t.Setenv("WHATAP_LOG_INTERVAL", "1m")
			input := &loggingEnvInput{}
			if err := runArgs([]string{arg}, input, io.Discard, nil); err == nil || input.read {
				t.Fatalf("valid environment masked invalid CLI: err=%v stdin_read=%v", err, input.read)
			}
		})
	}
}

func TestLoggingEnvironmentPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name     string
		env      map[string]string
		args     []string
		stdout   string
		level    string
		interval time.Duration
	}{
		{name: "unset keeps defaults", stdout: "auto", level: "info", interval: time.Minute},
		{name: "env replaces defaults", env: map[string]string{"WHATAP_STDOUT": "jsonl", "WHATAP_LOG_LEVEL": "warn", "WHATAP_LOG_INTERVAL": "30s"}, stdout: "jsonl", level: "warn", interval: 30 * time.Second},
		{name: "env disables periodic summaries", env: map[string]string{"WHATAP_STDOUT": "none", "WHATAP_LOG_LEVEL": "error", "WHATAP_LOG_INTERVAL": "0"}, stdout: "none", level: "error"},
		{name: "explicit defaults override invalid env", env: map[string]string{"WHATAP_STDOUT": "invalid", "WHATAP_LOG_LEVEL": "invalid", "WHATAP_LOG_INTERVAL": "invalid"}, args: []string{"-stdout", "auto", "-log-level", "info", "-log-interval", "1m"}, stdout: "auto", level: "info", interval: time.Minute},
		{name: "explicit flags override empty env", env: map[string]string{"WHATAP_STDOUT": "", "WHATAP_LOG_LEVEL": "", "WHATAP_LOG_INTERVAL": ""}, args: []string{"-stdout=jsonl", "-log-level=error", "-log-interval=0"}, stdout: "jsonl", level: "error"},
		{name: "per field precedence", env: map[string]string{"WHATAP_STDOUT": "none", "WHATAP_LOG_LEVEL": "debug", "WHATAP_LOG_INTERVAL": "2s"}, args: []string{"-stdout=jsonl"}, stdout: "jsonl", level: "debug", interval: 2 * time.Second},
		{name: "explicit zero wins", env: map[string]string{"WHATAP_LOG_INTERVAL": "bad"}, args: []string{"-log-interval=0"}, stdout: "auto", level: "info"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearLoggingEnvironment(t)
			for name, value := range tc.env {
				t.Setenv(name, value)
			}
			flags := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
			stdout := flags.String("stdout", "auto", "")
			level := flags.String("log-level", "info", "")
			interval := flags.Duration("log-interval", time.Minute, "")
			if err := flags.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			if err := applyLoggingEnvironment(flags); err != nil {
				t.Fatal(err)
			}
			if *stdout != tc.stdout || *level != tc.level || *interval != tc.interval {
				t.Fatalf("effective settings = %s/%s/%s, want %s/%s/%s", *stdout, *level, *interval, tc.stdout, tc.level, tc.interval)
			}
		})
	}
}

type loggingEnvInput struct{ read bool }

func (r *loggingEnvInput) Read([]byte) (int, error) { r.read = true; return 0, io.EOF }

func TestLoggingEnvironmentRejectsInvalidBeforeIO(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values []string
	}{
		{name: "WHATAP_STDOUT", values: []string{"", "JSONL", " none", "invalid-private-value"}},
		{name: "WHATAP_LOG_LEVEL", values: []string{"", "INFO", "debug ", "invalid-private-value"}},
		{name: "WHATAP_LOG_INTERVAL", values: []string{"", "-1s", "1", "999999999999999999999h", "invalid-private-value"}},
	} {
		for _, value := range tc.values {
			for _, source := range []string{"stdin", "ebpf"} {
				t.Run(tc.name+"/"+source+"/"+value, func(t *testing.T) {
					clearLoggingEnvironment(t)
					t.Setenv(tc.name, value)
					input := &loggingEnvInput{}
					opened := false
					err := runArgs([]string{"-source=" + source, "-pod-identity=false", "-conntrack=false", "-process=false"}, input, io.Discard, func(collector.OpenOptions) (collector.EventReader, error) {
						opened = true
						return nil, io.ErrUnexpectedEOF
					})
					if err == nil || !strings.Contains(err.Error(), tc.name) || input.read || opened {
						t.Fatalf("invalid env must be identified before I/O: err=%v stdin_read=%v opened=%v", err, input.read, opened)
					}
					if strings.Contains(err.Error(), "invalid-private-value") {
						t.Fatal("invalid environment value leaked into diagnostic")
					}
				})
			}
		}
	}
}
