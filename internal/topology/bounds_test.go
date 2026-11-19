package topology

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
)

func TestCapacityAcrossBucketsAllowsUpdatesAndDrainsDeterministically(t *testing.T) {
	config := Config{ClusterID: "cluster-a", WindowSize: time.Minute, MaxEntries: 2}
	a, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	first, second, third := testWindow(testStart.Add(time.Second)), testWindow(testStart.Add(time.Minute)), testWindow(testStart.Add(2*time.Minute))
	for _, w := range []flow.Window{second, first} {
		if err := a.ObserveWindow(w); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.ObserveWindow(third); err == nil {
		t.Fatal("saturation was silently accepted")
	}
	first.LastObservedAt = testStart.Add(2 * time.Second)
	if err := a.ObserveWindow(first); err != nil {
		t.Fatalf("existing key rejected at capacity: %v", err)
	}
	if a.Len() != config.MaxEntries {
		t.Fatalf("unbounded entries=%d", a.Len())
	}
	got := a.FlushBefore(testStart.Add(time.Minute))
	if len(got) != 1 || got[0].LastSeenMS != first.LastObservedAt.UnixMilli() || a.Len() != 1 {
		t.Fatalf("drain=%+v, len=%d", got, a.Len())
	}
	if err := a.ObserveWindow(third); err != nil {
		t.Fatalf("capacity not released: %v", err)
	}
	got = a.FlushAll()
	if len(got) != 2 || !got[0].WindowStart.Equal(testStart.Add(time.Minute)) || !got[1].WindowStart.Equal(testStart.Add(2*time.Minute)) {
		t.Fatalf("nondeterministic drain: %+v", got)
	}
	if a.Len() != 0 || len(a.FlushAll()) != 0 {
		t.Fatal("drain retained buckets")
	}
	// Reopening an old bucket is an idempotent correction, never a silent drop.
	if err := a.ObserveWindow(first); err != nil {
		t.Fatal(err)
	}
	late := a.FlushBefore(testStart.Add(3 * time.Minute))
	if len(late) != 1 || late[0].LastSeenMS != first.LastObservedAt.UnixMilli() {
		t.Fatalf("lost late evidence: %+v", late)
	}
	b, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []flow.Window{third, second} {
		if err := b.ObserveWindow(w); err != nil {
			t.Fatal(err)
		}
	}
	if reversed := b.FlushAll(); !reflect.DeepEqual(got, reversed) {
		t.Fatalf("order depends on arrival: %+v != %+v", got, reversed)
	}
}

func TestConfigRequiresExplicitBoundedClusterAndWindow(t *testing.T) {
	valid := Config{ClusterID: "cluster-a", WindowSize: time.Minute, MaxEntries: 1}
	for name, mutate := range map[string]func(*Config){
		"missing cluster":      func(c *Config) { c.ClusterID = "" },
		"whitespace cluster":   func(c *Config) { c.ClusterID = "cluster a" },
		"control cluster":      func(c *Config) { c.ClusterID = "cluster\na" },
		"unicode cluster":      func(c *Config) { c.ClusterID = "클러스터" },
		"oversize cluster":     func(c *Config) { c.ClusterID = strings.Repeat("a", 254) },
		"zero window":          func(c *Config) { c.WindowSize = 0 },
		"negative window":      func(c *Config) { c.WindowSize = -time.Second },
		"sub-ms window":        func(c *Config) { c.WindowSize = time.Microsecond },
		"fractional-ms window": func(c *Config) { c.WindowSize = time.Millisecond + time.Nanosecond },
		"oversize window":      func(c *Config) { c.WindowSize = time.Minute + time.Millisecond },
		"zero bound":           func(c *Config) { c.MaxEntries = 0 },
		"negative bound":       func(c *Config) { c.MaxEntries = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			c := valid
			mutate(&c)
			if a, err := New(c); err == nil || a != nil {
				t.Fatalf("accepted invalid config: %+v", c)
			}
		})
	}
	for _, size := range []time.Duration{time.Millisecond, 5 * time.Second, time.Minute} {
		c := valid
		c.WindowSize = size
		if _, err := New(c); err != nil {
			t.Fatalf("valid config: %v", err)
		}
	}
}
