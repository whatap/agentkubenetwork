package main

import (
	"flag"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func clearTopologyEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{"WHATAP_TOPOLOGY_SUMMARY", "WHATAP_TOPOLOGY_CLUSTER_ID", "WHATAP_TOPOLOGY_WINDOW", "WHATAP_TOPOLOGY_MAX_ENTRIES"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCLITopologyEnvironmentEnablesOptInGuard(t *testing.T) {
	clearLoggingEnvironment(t)
	clearTopologyEnvironment(t)
	t.Setenv("WHATAP_TOPOLOGY_SUMMARY", "true")
	input := &loggingEnvInput{}
	err := runArgs(nil, input, io.Discard, nil)
	if err == nil || !strings.Contains(err.Error(), "topology summary requires -source=ebpf") || input.read {
		t.Fatalf("environment opt-in ignored: err=%v stdin_read=%v", err, input.read)
	}
}

func TestTopologyEnvironmentValuesAndPrecedence(t *testing.T) {
	for _, cliOverride := range []bool{false, true} {
		t.Run(map[bool]string{false: "env", true: "cli"}[cliOverride], func(t *testing.T) {
			clearTopologyEnvironment(t)
			for name, value := range map[string]string{"WHATAP_TOPOLOGY_SUMMARY": "true", "WHATAP_TOPOLOGY_CLUSTER_ID": "cluster-env", "WHATAP_TOPOLOGY_WINDOW": "30s", "WHATAP_TOPOLOGY_MAX_ENTRIES": "128"} {
				t.Setenv(name, value)
			}
			flags := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
			enabled := flags.Bool("topology-summary", false, "")
			cluster := flags.String("topology-cluster-id", "", "")
			window := flags.Duration("topology-window", time.Minute, "")
			entries := flags.Int("topology-max-entries", 4096, "")
			var args []string
			if cliOverride {
				args = []string{"-topology-summary=false", "-topology-cluster-id=cluster-cli", "-topology-window=1m", "-topology-max-entries=4096"}
				// Explicit values must also supersede malformed environment values.
				t.Setenv("WHATAP_TOPOLOGY_SUMMARY", "invalid")
				t.Setenv("WHATAP_TOPOLOGY_WINDOW", "invalid")
				t.Setenv("WHATAP_TOPOLOGY_MAX_ENTRIES", "invalid")
			}
			if err := flags.Parse(args); err != nil {
				t.Fatal(err)
			}
			if err := applyTopologyEnvironment(flags); err != nil {
				t.Fatal(err)
			}
			if cliOverride {
				if *enabled || *cluster != "cluster-cli" || *window != time.Minute || *entries != 4096 {
					t.Fatal("explicit CLI values were replaced")
				}
			} else if !*enabled || *cluster != "cluster-env" || *window != 30*time.Second || *entries != 128 {
				t.Fatal("environment values were not applied")
			}
		})
	}
}

func TestCLITopologyEnvironmentValidationBeforeIO(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		args []string
		want string
	}{
		{name: "empty cluster", env: map[string]string{"WHATAP_TOPOLOGY_SUMMARY": "true", "WHATAP_TOPOLOGY_CLUSTER_ID": ""}, want: "topology-cluster-id"},
		{name: "unused cluster", env: map[string]string{"WHATAP_TOPOLOGY_CLUSTER_ID": "cluster-a"}, want: "requires -topology-summary"},
		{name: "bad boolean", env: map[string]string{"WHATAP_TOPOLOGY_SUMMARY": "private-value"}, want: "WHATAP_TOPOLOGY_SUMMARY"},
		{name: "empty boolean", env: map[string]string{"WHATAP_TOPOLOGY_SUMMARY": ""}, want: "WHATAP_TOPOLOGY_SUMMARY"},
		{name: "bad duration", env: map[string]string{"WHATAP_TOPOLOGY_WINDOW": "private-value"}, want: "WHATAP_TOPOLOGY_WINDOW"},
		{name: "bad integer", env: map[string]string{"WHATAP_TOPOLOGY_MAX_ENTRIES": "private-value"}, want: "WHATAP_TOPOLOGY_MAX_ENTRIES"},
		{name: "bad cluster", env: map[string]string{"WHATAP_TOPOLOGY_SUMMARY": "true", "WHATAP_TOPOLOGY_CLUSTER_ID": "private-value with spaces"}, want: "topology-cluster-id"},
		{name: "window bound", env: map[string]string{"WHATAP_TOPOLOGY_SUMMARY": "true", "WHATAP_TOPOLOGY_CLUSTER_ID": "cluster-a", "WHATAP_TOPOLOGY_WINDOW": "2m"}, want: "topology window"},
		{name: "entry bound", env: map[string]string{"WHATAP_TOPOLOGY_SUMMARY": "true", "WHATAP_TOPOLOGY_CLUSTER_ID": "cluster-a", "WHATAP_TOPOLOGY_MAX_ENTRIES": "65537"}, want: "topology max entries"},
		{name: "CLI bound", env: map[string]string{"WHATAP_TOPOLOGY_SUMMARY": "true", "WHATAP_TOPOLOGY_CLUSTER_ID": "cluster-a", "WHATAP_TOPOLOGY_MAX_ENTRIES": "128"}, args: []string{"-topology-max-entries=0"}, want: "topology max entries"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearLoggingEnvironment(t)
			clearTopologyEnvironment(t)
			for name, value := range tc.env {
				t.Setenv(name, value)
			}
			input := &loggingEnvInput{}
			args := append([]string{"-source=ebpf", "-export=tagcount"}, tc.args...)
			err := runArgs(args, input, io.Discard, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) || input.read {
				t.Fatalf("validation mismatch before I/O: err=%v stdin_read=%v", err, input.read)
			}
			if strings.Contains(err.Error(), "private-value") {
				t.Fatal("environment value leaked into error")
			}
		})
	}
}
