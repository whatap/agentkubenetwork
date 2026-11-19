package main

import (
	"io"
	"strings"
	"testing"

	"github.com/whatap/agentkubenetwork/internal/collector"
)

func TestCLITopologyRequiresExplicitSafeConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"stdin", []string{"-topology-summary"}, "topology summary requires -source=ebpf"},
		{"no export", []string{"-source=ebpf", "-topology-summary"}, "topology summary requires -export=tagcount"},
		{"no identity", []string{"-source=ebpf", "-export=tagcount", "-pod-identity=false", "-topology-summary"}, "topology summary requires -pod-identity"},
		{"empty cluster", []string{"-source=ebpf", "-export=tagcount", "-topology-summary", "-topology-cluster-id="}, "topology-cluster-id"},
		{"oversized window", []string{"-source=ebpf", "-export=tagcount", "-topology-summary", "-topology-cluster-id=cluster-a", "-topology-window=2m"}, "topology window"},
		{"fractional ms", []string{"-source=ebpf", "-export=tagcount", "-topology-summary", "-topology-cluster-id=cluster-a", "-topology-window=1500us"}, "topology window"},
		{"zero bound", []string{"-source=ebpf", "-export=tagcount", "-topology-summary", "-topology-cluster-id=cluster-a", "-topology-max-entries=0"}, "topology max entries"},
		{"oversized bound", []string{"-source=ebpf", "-export=tagcount", "-topology-summary", "-topology-cluster-id=cluster-a", "-topology-max-entries=65537"}, "topology max entries"},
		{"unused cluster", []string{"-topology-cluster-id=cluster-a"}, "requires -topology-summary"},
		{"unused window", []string{"-topology-window=10s"}, "requires -topology-summary"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opened := false
			err := runArgs(tc.args, strings.NewReader(""), io.Discard, func(collector.OpenOptions) (collector.EventReader, error) {
				opened = true
				return &cliEventReader{}, nil
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) || opened {
				t.Fatalf("validation mismatch: err=%v opened=%v want=%q", err, opened, tc.want)
			}
		})
	}
}

func TestCLITopologyDefaultDoesNotEnableNewInformers(t *testing.T) {
	// The mock only serves Pod requests; any additional controller LIST/WATCH
	// would fail this existing end-to-end CLI exercise.
	testCLIPodInformer(t, nil)
}
