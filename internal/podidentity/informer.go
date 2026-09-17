package podidentity

import (
	"context"
	"errors"
	"fmt"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	typed "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"time"
)

// Start runs exactly one cluster-wide Pod SharedIndexInformer. No lookup issues
// API calls. The caller must stop it after the event pipeline has drained.
func Start(parent context.Context, config *rest.Config, syncTimeout time.Duration) (*Cache, func() error, error) {
	if parent == nil || config == nil || syncTimeout <= 0 {
		return nil, nil, errors.New("pod informer requires context, config and positive sync timeout")
	}
	client, err := typed.NewForConfig(config)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	pods := client.Pods(meta.NamespaceAll)
	informer := cache.NewSharedIndexInformer(&cache.ListWatch{
		ListWithContextFunc: func(ctx context.Context, options meta.ListOptions) (runtime.Object, error) {
			return pods.List(ctx, options)
		},
		WatchFuncWithContext: func(ctx context.Context, options meta.ListOptions) (watch.Interface, error) {
			return pods.Watch(ctx, options)
		},
	}, &core.Pod{}, 0, Indexers())
	done := make(chan struct{})
	go func() { defer close(done); informer.RunWithContext(ctx) }()
	stop := func() error {
		cancel()
		select {
		case <-done:
			return nil
		case <-time.After(syncTimeout):
			return errors.New("pod informer shutdown timeout")
		}
	}
	syncCtx, syncCancel := context.WithTimeout(ctx, syncTimeout)
	defer syncCancel()
	if !cache.WaitForCacheSync(syncCtx.Done(), informer.HasSynced) {
		return nil, nil, errors.Join(fmt.Errorf("pod informer sync: %w", syncCtx.Err()), stop())
	}
	return &Cache{index: informer.GetIndexer(), synced: func() bool { return ctx.Err() == nil && informer.HasSynced() }}, stop, nil
}
