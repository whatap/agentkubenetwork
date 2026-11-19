package podidentity

import (
	"context"
	"encoding/json"
	"errors"

	"k8s.io/client-go/tools/cache"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

type workloadAPIResource struct {
	list     any
	gate     chan struct{}
	listed   chan struct{}
	watched  chan struct{}
	closed   chan struct{}
	events   chan any
	requests atomic.Int32
}

func newWorkloadAPI(t *testing.T) (*rest.Config, map[string]*workloadAPIResource) {
	t.Helper()
	p := workloadPod()
	p.OwnerReferences = []meta.OwnerReference{controller("apps/v1", "ReplicaSet", "rs", "rs-uid")}
	q := p.DeepCopy()
	q.Name, q.UID, q.Status.PodIP = "job-pod", "job-pod-uid", "10.0.0.2"
	q.OwnerReferences = []meta.OwnerReference{controller("batch/v1", "Job", "job", "job-uid")}
	resources := map[string]*workloadAPIResource{
		"/api/v1/pods": {list: core.PodList{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "PodList"}, ListMeta: meta.ListMeta{ResourceVersion: "17"}, Items: []core.Pod{*p, *q}}},
	}
	for path, object := range map[string]meta.ObjectMeta{
		"/apis/apps/v1/replicasets": {Namespace: "ns", Name: "rs", UID: "rs-uid", OwnerReferences: []meta.OwnerReference{controller("apps/v1", "Deployment", "web", "deployment-uid")}},
		"/apis/batch/v1/jobs":       {Namespace: "ns", Name: "job", UID: "job-uid", OwnerReferences: []meta.OwnerReference{controller("batch/v1", "CronJob", "nightly", "cronjob-uid")}},
	} {
		resources[path] = &workloadAPIResource{list: meta.PartialObjectMetadataList{TypeMeta: meta.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadataList"}, ListMeta: meta.ListMeta{ResourceVersion: "17"}, Items: []meta.PartialObjectMetadata{{ObjectMeta: object}}}}
	}
	for _, resource := range resources {
		resource.gate = make(chan struct{})
		resource.listed = make(chan struct{}, 16)
		resource.watched = make(chan struct{}, 16)
		resource.closed = make(chan struct{}, 16)
		resource.events = make(chan any, 16)
	}
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resource := resources[r.URL.Path]
		if resource == nil {
			t.Errorf("unexpected API path %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		resource.requests.Add(1)
		if r.URL.Path != "/api/v1/pods" && !strings.Contains(r.Header.Get("Accept"), "as=PartialObjectMetadata") {
			t.Errorf("not metadata-only: %s", r.Header.Get("Accept"))
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("watch") != "true" {
			resource.listed <- struct{}{}
			select {
			case <-resource.gate:
				_ = json.NewEncoder(w).Encode(resource.list)
			case <-r.Context().Done():
				resource.closed <- struct{}{}
			case <-done:
			}
			return
		}
		if rv := r.URL.Query().Get("resourceVersion"); rv != "17" {
			t.Errorf("WATCH resourceVersion = %q", rv)
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		resource.watched <- struct{}{}
		defer func() { resource.closed <- struct{}{} }()
		for {
			select {
			case event := <-resource.events:
				_ = json.NewEncoder(w).Encode(event)
				w.(http.Flusher).Flush()
			case <-r.Context().Done():
				return
			case <-done:
				return
			}
		}
	}))
	t.Cleanup(func() { close(done); server.Close() })
	return &rest.Config{Host: server.URL}, resources
}

func awaitWorkloadSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for API lifecycle signal")
	}
}

func TestWorkloadMetadataDeletion(t *testing.T) {
	for _, kind := range []string{"Pod", "ReplicaSet", "Job"} {
		for _, tombstone := range []string{"direct", "value", "pointer"} {
			t.Run(kind+"/"+tombstone, func(t *testing.T) {
				w := newWorkloadCache()
				h := workloadMetadataHandler(w, kind)
				old := &meta.PartialObjectMetadata{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "same", UID: "old"}}
				replacement := old.DeepCopy()
				replacement.UID = "new"
				h.OnAdd(old, false)
				h.OnUpdate(old, replacement)
				wrap := func(obj any) any {
					switch tombstone {
					case "value":
						return cache.DeletedFinalStateUnknown{Key: "ns/same", Obj: obj}
					case "pointer":
						return &cache.DeletedFinalStateUnknown{Key: "ns/same", Obj: obj}
					default:
						return obj
					}
				}
				h.OnDelete(wrap(old))
				h.OnDelete(cache.DeletedFinalStateUnknown{Key: "ns/same"})
				withoutUID := replacement.DeepCopy()
				withoutUID.UID = ""
				h.OnDelete(wrap(withoutUID))
				if got := w.objects[workloadKey{kind, "ns", "same"}]; got.UID != "new" {
					t.Fatalf("stale/unknown delete removed replacement: %+v", got)
				}
				h.OnDelete(wrap(replacement))
				h.OnDelete(wrap(replacement))
				if len(w.objects) != 0 {
					t.Fatalf("metadata retained after deletion: %v", w.objects)
				}
			})
		}
	}
}

func TestWorkloadInformerWaitsForEveryList(t *testing.T) {
	for _, blocked := range []string{"/api/v1/pods", "/apis/apps/v1/replicasets", "/apis/batch/v1/jobs"} {
		t.Run(blocked, func(t *testing.T) {
			config, resources := newWorkloadAPI(t)
			for path, resource := range resources {
				if path != blocked {
					close(resource.gate)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			type result struct {
				c    *Cache
				stop func() error
				err  error
			}
			ready := make(chan result, 1)
			go func() {
				c, stop, err := StartWithWorkloads(ctx, config, 2*time.Second)
				ready <- result{c, stop, err}
			}()
			for path, resource := range resources {
				awaitWorkloadSignal(t, resource.listed)
				if path != blocked {
					awaitWorkloadSignal(t, resource.watched)
				}
			}
			select {
			case got := <-ready:
				if got.stop != nil {
					_ = got.stop()
				}
				t.Fatalf("returned before %s synced: %v", blocked, got.err)
			case <-time.After(150 * time.Millisecond):
			}
			close(resources[blocked].gate)
			select {
			case got := <-ready:
				if got.err != nil {
					t.Fatal(got.err)
				}
				if !got.c.synced() {
					t.Error("cache not ready")
				}
				if err := got.stop(); err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("did not become ready")
			}
		})
	}
}

func TestWorkloadInformerTimeoutRollsBackEveryResource(t *testing.T) {
	for _, blocked := range []string{"/api/v1/pods", "/apis/apps/v1/replicasets", "/apis/batch/v1/jobs"} {
		t.Run(blocked, func(t *testing.T) {
			config, resources := newWorkloadAPI(t)
			for path, resource := range resources {
				if path != blocked {
					close(resource.gate)
				}
			}
			started := time.Now()
			c, stop, err := StartWithWorkloads(context.Background(), config, 400*time.Millisecond)
			if c != nil || stop != nil || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("timeout result: cache=%v stopPresent=%t error=%v", c, stop != nil, err)
			}
			if time.Since(started) > 2*time.Second {
				t.Fatal("unbounded rollback")
			}
			for _, resource := range resources {
				awaitWorkloadSignal(t, resource.closed)
			}
		})
	}
}

func waitWorkloadCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("informer event was not applied")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestWorkloadInformerWatchUpdatesAndDeletes(t *testing.T) {
	config, resources := newWorkloadAPI(t)
	for _, resource := range resources {
		close(resource.gate)
	}
	c, stop, err := StartWithWorkloads(context.Background(), config, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	for _, resource := range resources {
		awaitWorkloadSignal(t, resource.watched)
	}
	changed := &meta.PartialObjectMetadata{
		TypeMeta:   meta.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"},
		ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "rs", UID: "rs-uid", ResourceVersion: "18", OwnerReferences: []meta.OwnerReference{controller("apps/v1", "Deployment", "changed", "changed-uid")}},
	}
	before := time.Now()
	resources["/apis/apps/v1/replicasets"].events <- map[string]any{"type": "MODIFIED", "object": changed}
	waitWorkloadCondition(t, func() bool {
		p := c.lookup("ip", "10.0.0.1", time.Now())
		return p != nil && p.WorkloadUID == "changed-uid"
	})
	assertWorkload(t, c.lookup("ip", "10.0.0.1", before), "", "", "")
	for _, resource := range resources {
		switch list := resource.list.(type) {
		case core.PodList:
			for _, object := range list.Items {
				object.TypeMeta = meta.TypeMeta{APIVersion: "v1", Kind: "Pod"}
				object.ResourceVersion = "19"
				resource.events <- map[string]any{"type": "DELETED", "object": object}
			}
		case meta.PartialObjectMetadataList:
			for _, object := range list.Items {
				object.TypeMeta = changed.TypeMeta
				object.ResourceVersion = "19"
				resource.events <- map[string]any{"type": "DELETED", "object": object}
			}
		}
	}
	waitWorkloadCondition(t, func() bool {
		c.workloads.mu.RLock()
		defer c.workloads.mu.RUnlock()
		return len(c.workloads.objects) == 0 && len(c.index.List()) == 0
	})
}

func TestWorkloadInformerParentCancellationDuringSync(t *testing.T) {
	config, resources := newWorkloadAPI(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, stop, err := StartWithWorkloads(ctx, config, 2*time.Second)
		if stop != nil {
			_ = stop()
		}
		result <- err
	}()
	for _, resource := range resources {
		awaitWorkloadSignal(t, resource.listed)
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel result: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("startup cancellation did not return")
	}
	for _, resource := range resources {
		awaitWorkloadSignal(t, resource.closed)
	}
}

func TestStartRemainsPodsOnly(t *testing.T) {
	config, resources := newWorkloadAPI(t)
	close(resources["/api/v1/pods"].gate)
	c, stop, err := Start(context.Background(), config, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if c.workloads != nil {
		t.Fatal("default Start enabled workloads")
	}
	assertWorkload(t, c.lookup("ip", "10.0.0.1", time.Now()), "", "", "")
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	for path, resource := range resources {
		if path != "/api/v1/pods" && resource.requests.Load() != 0 {
			t.Errorf("default Start requested %s", path)
		}
	}
}

func TestWorkloadInformerSyncAndCancellation(t *testing.T) {
	config, resources := newWorkloadAPI(t)
	for _, resource := range resources {
		close(resource.gate)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	before := time.Now()
	c, stop, err := StartWithWorkloads(ctx, config, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if !c.synced() {
		t.Fatal("returned before ready")
	}
	assertWorkload(t, c.lookup("ip", "10.0.0.1", time.Now()), "deployment-uid", "web", "Deployment")
	job := c.lookup("ip", "10.0.0.2", time.Now())
	if job == nil || job.WorkloadUID != "cronjob-uid" || job.WorkloadKind != "CronJob" {
		t.Fatalf("Job chain not ready: %+v", job)
	}
	assertWorkload(t, c.lookup("ip", "10.0.0.1", before), "", "", "")
	for _, resource := range resources {
		awaitWorkloadSignal(t, resource.watched)
	}
	cancel()
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if err := stop(); err != nil {
		t.Fatalf("repeated stop: %v", err)
	}
	for _, resource := range resources {
		awaitWorkloadSignal(t, resource.closed)
	}
	if c.synced() || c.lookup("ip", "10.0.0.1", time.Now()) != nil {
		t.Fatal("cancelled cache remains ready")
	}
}
