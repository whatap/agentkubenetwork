package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/collector"
	"github.com/whatap/agentkubenetwork/internal/flow"
)

func TestCLIPodInformerExplicitConfig(t *testing.T) {
	testCLIPodInformer(t, []string{"-pod-identity=true"})
}

func TestCLIPodInformerDefaultsOnForEBPF(t *testing.T) {
	t.Setenv("WHATAP_ACCESSKEY", "invalid-should-not-enable-export")
	testCLIPodInformer(t, nil)
}

func testCLIPodInformer(t *testing.T, podArgs []string) {
	t.Helper()
	var lists, watches atomic.Int32
	disconnected := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/pods" {
			t.Errorf("unexpected API %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("watch") == "true" {
			watches.Add(1)
			if got := r.URL.Query().Get("resourceVersion"); got != "1" {
				t.Errorf("WATCH resourceVersion = %q, want 1", got)
			}
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			disconnected <- struct{}{}
			return
		}
		lists.Add(1)
		io.WriteString(w, `{"kind":"PodList","apiVersion":"v1","metadata":{"resourceVersion":"1"},"items":[{"metadata":{"name":"pod","namespace":"ns","uid":"pod-uid"},"status":{"podIP":"10.0.0.2"}}]}`)
	}))
	defer server.Close()
	config := writeCLIKubeconfig(t, server.URL)
	var output bytes.Buffer
	reader := &cliEventReader{}
	args := append([]string{"-source=ebpf", "-kubeconfig=" + config, "-pod-sync-timeout=1s", "-conntrack=false", "-process=false"}, podArgs...)
	err := runArgs(args, strings.NewReader(""), &output, func(collector.OpenOptions) (collector.EventReader, error) {
		if lists.Load() != 1 {
			t.Errorf("BPF opened before initial Pod LIST: lists=%d", lists.Load())
		}
		return reader, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var o flow.Observation
	if err := json.NewDecoder(&output).Decode(&o); err != nil {
		t.Fatal(err)
	}
	if o.DestinationPod == nil || o.DestinationPod.UID != "pod-uid" {
		t.Fatalf("CLI not enriched: %+v", o)
	}
	if lists.Load() != 1 || watches.Load() != 1 || !reader.closed {
		t.Fatalf("informer lifecycle: lists=%d watches=%d reader.closed=%v", lists.Load(), watches.Load(), reader.closed)
	}
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("Pod watch not canceled on CLI shutdown")
	}
}

func writeCLIKubeconfig(t *testing.T, serverURL string) string {
	t.Helper()
	config := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(config, []byte("apiVersion: v1\nkind: Config\nclusters:\n- name: local\n  cluster:\n    server: "+serverURL+"\ncontexts:\n- name: local\n  context:\n    cluster: local\ncurrent-context: local\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return config
}

func TestCLIStdinRejectsExplicitPodSyncTimeout(t *testing.T) {
	for _, args := range [][]string{
		{"-pod-sync-timeout=1s"},
		{"-source=stdin", "-pod-sync-timeout=0"},
		{"-source=stdin", "-pod-identity=false", "-pod-sync-timeout=10s"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			opened := false
			err := runArgs(args, strings.NewReader(""), io.Discard, func(collector.OpenOptions) (collector.EventReader, error) {
				opened = true
				return &cliEventReader{}, nil
			})
			if err == nil || !strings.Contains(err.Error(), "requires -source=ebpf") || opened {
				t.Fatalf("stdin accepted live Pod sync option: err=%v opened=%v", err, opened)
			}
		})
	}
}

func TestCLIRejectsInvalidPodOptionsBeforeAttaching(t *testing.T) {
	requests, config := cliAmbientKubeconfig(t)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-pod-identity"}, "pod identity requires -source=ebpf"},
		{[]string{"-source=stdin", "-pod-identity=true"}, "pod identity requires -source=ebpf"},
		{[]string{"-source=stdin", "-kubeconfig=" + config}, "-kubeconfig requires -pod-identity"},
		{[]string{"-source=ebpf", "-pod-identity=false", "-kubeconfig=" + config}, "-kubeconfig requires -pod-identity"},
		{[]string{"-source=ebpf", "-pod-sync-timeout=0"}, "positive -pod-sync-timeout"},
		{[]string{"-source=ebpf", "-pod-sync-timeout=-1s"}, "positive -pod-sync-timeout"},
		{[]string{"-source=ebpf", "-kubeconfig=" + filepath.Join(t.TempDir(), "missing")}, "pod identity configuration"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			opened := false
			err := runArgs(tc.args, strings.NewReader(""), io.Discard, func(collector.OpenOptions) (collector.EventReader, error) {
				opened = true
				return &cliEventReader{}, nil
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) || opened {
				t.Fatalf("invalid pod options: err=%v, want %q; opened=%v", err, tc.want, opened)
			}
		})
	}
	if requests.Load() != 0 {
		t.Fatalf("invalid Pod flags contacted Kubernetes: %d requests", requests.Load())
	}
}

func cliAmbientKubeconfig(t *testing.T) (*atomic.Int32, string) {
	t.Helper()
	requests := new(atomic.Int32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "unexpected Kubernetes access", http.StatusForbidden)
	}))
	t.Cleanup(server.Close)
	config := writeCLIKubeconfig(t, server.URL)
	t.Setenv("KUBECONFIG", config)
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	return requests, config
}

func TestCLIPodIdentityOptOutSkipsKubernetes(t *testing.T) {
	requests, _ := cliAmbientKubeconfig(t)
	reader := &cliEventReader{}
	var output bytes.Buffer
	err := runArgs([]string{"-source=ebpf", "-pod-identity=false", "-conntrack=false", "-process=false"}, strings.NewReader(""), &output, func(collector.OpenOptions) (collector.EventReader, error) {
		return reader, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var observation flow.Observation
	if err := json.NewDecoder(&output).Decode(&observation); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 || !reader.closed || observation.SourcePod != nil || observation.DestinationPod != nil {
		t.Fatalf("opt-out used Kubernetes or lost capture: requests=%d closed=%v observation=%+v", requests.Load(), reader.closed, observation)
	}
}

func TestCLIStdinDefaultRemainsClusterFree(t *testing.T) {
	requests, _ := cliAmbientKubeconfig(t)
	for _, args := range [][]string{nil, {"-source=stdin"}, {"-source=stdin", "-pod-identity=false"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var input, output bytes.Buffer
			observation := flow.Observation{
				ObservedAt: time.Date(2026, 8, 18, 0, 0, 1, 0, time.UTC),
				Flow: flow.FlowKey{NodeName: "node", Protocol: "tcp", Direction: "egress",
					Source: flow.Endpoint{Address: "10.0.0.1", Port: 41000}, Destination: flow.Endpoint{Address: "10.0.0.2", Port: 8080}},
				BytesTx: 123,
			}
			if err := json.NewEncoder(&input).Encode(observation); err != nil {
				t.Fatal(err)
			}
			opened := false
			err := runArgs(args, &input, &output, func(collector.OpenOptions) (collector.EventReader, error) {
				opened = true
				return &cliEventReader{}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			var window flow.Window
			decoder := json.NewDecoder(&output)
			if err := decoder.Decode(&window); err != nil {
				t.Fatal(err)
			}
			if opened || requests.Load() != 0 || window.ObservationCount != 1 || window.BytesTx != 123 || window.Flow != observation.Flow {
				t.Fatalf("stdin default changed: opened=%v requests=%d window=%+v", opened, requests.Load(), window)
			}
			if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
				t.Fatalf("unexpected extra stdin output: %v", err)
			}
		})
	}
}

func TestCLIPodDefaultIgnoresAmbientKubeconfig(t *testing.T) {
	const childEnv = "AGENTKUBENETWORK_TEST_AMBIENT_KUBECONFIG"
	if os.Getenv(childEnv) == "1" {
		opened := false
		err := runArgs([]string{"-source=ebpf", "-pod-sync-timeout=100ms", "-conntrack=false", "-process=false"}, strings.NewReader(""), io.Discard, func(collector.OpenOptions) (collector.EventReader, error) {
			opened = true
			return &cliEventReader{}, nil
		})
		if err == nil || !strings.Contains(err.Error(), "pod identity configuration") || opened {
			t.Fatalf("missing in-cluster config did not fail before attach: err=%v opened=%v", err, opened)
		}
		return
	}
	requests, config := cliAmbientKubeconfig(t)
	home := t.TempDir()
	homeConfig := filepath.Join(home, ".kube", "config")
	if err := os.MkdirAll(filepath.Dir(homeConfig), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(config, homeConfig); err != nil {
		t.Fatal(err)
	}
	for _, ambient := range []string{"environment", "home"} {
		t.Run(ambient, func(t *testing.T) {
			t.Setenv("HOME", home)
			t.Setenv("KUBECONFIG", "")
			if ambient == "environment" {
				t.Setenv("KUBECONFIG", homeConfig)
			}
			t.Setenv(childEnv, "1")
			// client-go resolves its default home path at process initialization.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCLIPodDefaultIgnoresAmbientKubeconfig$", "-test.v")
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("isolated kubeconfig probe: %v\n%s", err, output)
			}
		})
	}
	if requests.Load() != 0 {
		t.Fatalf("ambient kubeconfig used without explicit permission: %d requests", requests.Load())
	}
}

func TestCLIPodSyncFailureStopsBeforeAttaching(t *testing.T) {
	for _, mode := range []string{"forbidden", "blocked"} {
		t.Run(mode, func(t *testing.T) {
			var requests atomic.Int32
			disconnected := make(chan struct{}, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if mode == "blocked" {
					<-r.Context().Done()
					disconnected <- struct{}{}
					return
				}
				http.Error(w, "Pod LIST forbidden", http.StatusForbidden)
			}))
			defer server.Close()
			opened := false
			started := time.Now()
			err := runArgs([]string{"-source=ebpf", "-kubeconfig=" + writeCLIKubeconfig(t, server.URL), "-pod-sync-timeout=150ms"}, strings.NewReader(""), io.Discard, func(collector.OpenOptions) (collector.EventReader, error) {
				opened = true
				return &cliEventReader{}, nil
			})
			if !errors.Is(err, context.DeadlineExceeded) || opened || requests.Load() == 0 {
				t.Fatalf("Pod sync failure reached attach: err=%v opened=%v requests=%d", err, opened, requests.Load())
			}
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("unbounded Pod startup failure: %v", elapsed)
			}
			if mode == "blocked" {
				select {
				case <-disconnected:
				case <-time.After(time.Second):
					t.Fatal("failed Pod sync left its API request open")
				}
			}
		})
	}
}
