package podidentity

import (
	"reflect"
	"sync"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type workloadKey struct {
	kind, namespace, name string
}

type workloadMetadata struct {
	meta.ObjectMeta
	observedAt time.Time
}

// workloadCache contains only ownership metadata, never per-event API clients.
// A single lock makes each complete owner-chain lookup a value snapshot.
type workloadCache struct {
	mu      sync.RWMutex
	objects map[workloadKey]workloadMetadata
}

func newWorkloadCache() *workloadCache {
	return &workloadCache{objects: make(map[workloadKey]workloadMetadata)}
}

func (w *workloadCache) observe(kind string, obj meta.Object, at time.Time) {
	m := ownershipMetadata(obj)
	key := workloadKey{kind: kind, namespace: m.Namespace, name: m.Name}
	w.mu.Lock()
	defer w.mu.Unlock()
	if previous, ok := w.objects[key]; ok && reflect.DeepEqual(previous.ObjectMeta, m) {
		return // Status/label/resourceVersion churn does not change ownership.
	}
	w.objects[key] = workloadMetadata{ObjectMeta: *m.DeepCopy(), observedAt: at}
}

func (w *workloadCache) delete(kind string, obj meta.Object) {
	// Never let an old tombstone evict a same-name replacement. An object
	// without a UID cannot prove which generation was deleted.
	if obj.GetUID() == "" {
		return
	}
	key := workloadKey{kind: kind, namespace: obj.GetNamespace(), name: obj.GetName()}
	w.mu.Lock()
	defer w.mu.Unlock()
	if current, ok := w.objects[key]; ok && current.UID == obj.GetUID() {
		delete(w.objects, key)
	}
}

func ownershipMetadata(obj meta.Object) meta.ObjectMeta {
	return meta.ObjectMeta{Namespace: obj.GetNamespace(), Name: obj.GetName(), UID: obj.GetUID(), CreationTimestamp: obj.GetCreationTimestamp(), OwnerReferences: obj.GetOwnerReferences()}
}

func (m workloadMetadata) validAt(at time.Time) bool {
	// This is a current cache, not a historical owner database. Even an old
	// object first seen after the event cannot establish its then-owner.
	return !at.IsZero() && !at.Before(m.observedAt) && !at.Before(m.CreationTimestamp.Time)
}

// controllingOwner rejects malformed and ambiguous controllers instead of
// choosing the first reference or inferring a controller from a Pod name.
func controllingOwner(refs []meta.OwnerReference) (meta.OwnerReference, bool) {
	var owner meta.OwnerReference
	count := 0
	for _, ref := range refs {
		if ref.Controller != nil && *ref.Controller {
			owner = ref
			count++
		}
	}
	return owner, count == 1 && owner.UID != "" && owner.Name != ""
}

func knownTopLevel(owner meta.OwnerReference) bool {
	switch owner.APIVersion {
	case "apps/v1":
		return owner.Kind == "Deployment" || owner.Kind == "StatefulSet" || owner.Kind == "DaemonSet"
	case "batch/v1":
		return owner.Kind == "CronJob"
	case "v1":
		return owner.Kind == "ReplicationController"
	default:
		return false
	}
}

func (w *workloadCache) resolve(p *core.Pod, result *flow.Pod, at time.Time) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	m, ok := w.objects[workloadKey{kind: "Pod", namespace: p.Namespace, name: p.Name}]
	if !ok || !reflect.DeepEqual(m.ObjectMeta, ownershipMetadata(p)) || !m.validAt(at) {
		return
	}
	owner, ok := controllingOwner(m.OwnerReferences)
	if !ok {
		return
	}
	parentKind, topVersion, topKind := "", "", ""
	switch {
	case owner.APIVersion == "apps/v1" && owner.Kind == "ReplicaSet":
		parentKind, topVersion, topKind = "ReplicaSet", "apps/v1", "Deployment"
	case owner.APIVersion == "batch/v1" && owner.Kind == "Job":
		parentKind, topVersion, topKind = "Job", "batch/v1", "CronJob"
	}
	if parentKind != "" {
		parent, found := w.objects[workloadKey{kind: parentKind, namespace: p.Namespace, name: owner.Name}]
		if !found || parent.UID != owner.UID || !parent.validAt(at) {
			return
		}
		if len(parent.OwnerReferences) == 0 {
			// Only a UID-matching, ownerless cached ReplicaSet or Job can be
			// called standalone. A missing parent is never a name fallback.
			result.WorkloadUID, result.WorkloadName, result.WorkloadKind = string(parent.UID), parent.Name, parentKind
			return
		}
		owner, ok = controllingOwner(parent.OwnerReferences)
		if !ok || owner.APIVersion != topVersion || owner.Kind != topKind {
			return
		}
	}
	if !knownTopLevel(owner) {
		return
	}
	result.WorkloadUID, result.WorkloadName, result.WorkloadKind = string(owner.UID), owner.Name, owner.Kind
}
