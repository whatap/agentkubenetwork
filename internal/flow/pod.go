package flow

import "cmp"

// Pod is a cache-derived Kubernetes identity, never an IP-based surrogate UID.
type Pod struct {
	UID       string `json:"uid"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

func comparePod(a, b *Pod) int {
	if a == nil && b == nil {
		return 0
	}
	if a == nil {
		return -1
	}
	if b == nil {
		return 1
	}
	return cmp.Or(cmp.Compare(a.UID, b.UID), cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
}
