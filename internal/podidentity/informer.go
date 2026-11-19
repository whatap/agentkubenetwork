package podidentity

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	typed "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// Start runs exactly one cluster-wide Pod SharedIndexInformer. No lookup issues
// API calls. The caller must stop it after the event pipeline has drained.
func Start(parent context.Context, config *rest.Config, syncTimeout time.Duration) (*Cache, func() error, error) {
	return startInformers(parent, config, syncTimeout, false)
}

// StartWithWorkloads also watches ReplicaSet and Job ownership metadata. It
// returns only after all indexes and initial metadata callbacks have synced.
func StartWithWorkloads(parent context.Context, config *rest.Config, syncTimeout time.Duration) (*Cache, func() error, error) {
	return startInformers(parent, config, syncTimeout, true)
}

func startInformers(parent context.Context, config *rest.Config, syncTimeout time.Duration, withWorkloads bool) (*Cache, func() error, error) {
	if parent == nil || config == nil || syncTimeout <= 0 {
		return nil, nil, errors.New("pod informer requires context, config and positive sync timeout")
	}
	client, err := typed.NewForConfig(config)
	if err != nil {
		return nil, nil, err
	}
	pods := client.Pods(meta.NamespaceAll)
	podInformer := cache.NewSharedIndexInformer(&cache.ListWatch{
		ListWithContextFunc: func(ctx context.Context, options meta.ListOptions) (runtime.Object, error) {
			return pods.List(ctx, options)
		},
		WatchFuncWithContext: func(ctx context.Context, options meta.ListOptions) (watch.Interface, error) {
			return pods.Watch(ctx, options)
		},
	}, &core.Pod{}, 0, Indexers())
	informers := []cache.SharedIndexInformer{podInformer}
	syncs := []cache.InformerSynced{podInformer.HasSynced}
	result := &Cache{index: podInformer.GetIndexer()}
	if withWorkloads {
		metadataClient, err := metadata.NewForConfig(config)
		if err != nil {
			return nil, nil, err
		}
		result.workloads = newWorkloadCache()
		for _, resource := range []schema.GroupVersionResource{
			{Group: "apps", Version: "v1", Resource: "replicasets"},
			{Group: "batch", Version: "v1", Resource: "jobs"},
		} {
			objects := metadataClient.Resource(resource).Namespace(meta.NamespaceAll)
			informer := cache.NewSharedIndexInformer(&cache.ListWatch{
				ListWithContextFunc: func(ctx context.Context, options meta.ListOptions) (runtime.Object, error) {
					return objects.List(ctx, options)
				},
				WatchFuncWithContext: func(ctx context.Context, options meta.ListOptions) (watch.Interface, error) {
					return objects.Watch(ctx, options)
				},
			}, &meta.PartialObjectMetadata{}, 0, cache.Indexers{})
			informers = append(informers, informer)
			syncs = append(syncs, informer.HasSynced)
		}
		for i, kind := range []string{"Pod", "ReplicaSet", "Job"} {
			registration, err := informers[i].AddEventHandler(workloadMetadataHandler(result.workloads, kind))
			if err != nil {
				return nil, nil, err
			}
			// Index sync alone does not guarantee delivery to event handlers.
			syncs = append(syncs, registration.HasSynced)
		}
	}
	ctx, cancel := context.WithCancel(parent)
	var workers sync.WaitGroup
	for _, informer := range informers {
		workers.Add(1)
		go func(informer cache.SharedIndexInformer) {
			defer workers.Done()
			informer.RunWithContext(ctx)
		}(informer)
	}
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	stop := func() error {
		cancel()
		timer := time.NewTimer(syncTimeout)
		defer timer.Stop()
		select {
		case <-done:
			return nil
		case <-timer.C:
			return errors.New("pod informer shutdown timeout")
		}
	}
	syncCtx, syncCancel := context.WithTimeout(ctx, syncTimeout)
	defer syncCancel()
	if !cache.WaitForCacheSync(syncCtx.Done(), syncs...) {
		return nil, nil, errors.Join(fmt.Errorf("pod informer sync: %w", syncCtx.Err()), stop())
	}
	result.synced = func() bool {
		if ctx.Err() != nil {
			return false
		}
		for _, synced := range syncs {
			if !synced() {
				return false
			}
		}
		return true
	}
	return result, stop, nil
}

func workloadMetadataHandler(workloads *workloadCache, kind string) cache.ResourceEventHandlerFuncs {
	observe := func(obj any) {
		if m, ok := obj.(meta.Object); ok {
			workloads.observe(kind, m, time.Now())
		}
	}
	return cache.ResourceEventHandlerFuncs{
		AddFunc:    observe,
		UpdateFunc: func(_, obj any) { observe(obj) },
		DeleteFunc: func(obj any) {
			switch tombstone := obj.(type) {
			case cache.DeletedFinalStateUnknown:
				obj = tombstone.Obj
			case *cache.DeletedFinalStateUnknown:
				if tombstone == nil {
					return
				}
				obj = tombstone.Obj
			}
			if m, ok := obj.(meta.Object); ok {
				workloads.delete(kind, m)
			}
		},
	}
}
