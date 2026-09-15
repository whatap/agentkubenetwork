package dns

import "container/heap"

// pendingHeap holds exactly one indexed entry per pending query. Removal is
// eager, including on response/replacement, so stale deadlines cannot grow
// independently of MaxPending or expire a newer use of the same key.
type pendingHeap []*pendingQuery

func (h pendingHeap) Len() int { return len(h) }
func (h pendingHeap) Less(i, j int) bool {
	if h[i].fragment.ObservedAt.Equal(h[j].fragment.ObservedAt) {
		return h[i].sequence < h[j].sequence
	}
	return h[i].fragment.ObservedAt.Before(h[j].fragment.ObservedAt)
}
func (h pendingHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index, h[j].index = i, j
}
func (h *pendingHeap) Push(value any) {
	query := value.(*pendingQuery)
	query.index = len(*h)
	*h = append(*h, query)
}
func (h *pendingHeap) Pop() any {
	old := *h
	last := len(old) - 1
	query := old[last]
	old[last] = nil // Do not retain enrichment through the backing array.
	query.index = -1
	*h = old[:last]
	return query
}

func (c *Correlator) remove(query *pendingQuery) {
	heap.Remove(&c.deadlines, query.index)
	delete(c.pending, query.key)
}
