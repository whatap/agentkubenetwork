package conntrack

import (
	"errors"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
)

func safetyEntry() Entry {
	client := flow.Endpoint{Address: "10.0.0.1", Port: 41000}
	return Entry{Original: Tuple{Protocol: protocolNumberTCP, Source: client, Destination: flow.Endpoint{Address: "172.30.0.1", Port: 80}}, Reply: Tuple{Protocol: protocolNumberTCP, Source: flow.Endpoint{Address: "10.0.0.2", Port: 8080}, Destination: client}}
}

func TestResolverRejectsConflictingEntries(t *testing.T) {
	first := safetyEntry()
	for _, kind := range []string{"different_backend", "non_nat", "different_reply_destination"} {
		t.Run(kind, func(t *testing.T) {
			second := first
			switch kind {
			case "different_backend":
				second.Reply.Source.Address = "10.0.0.3"
			case "non_nat":
				second.Reply.Source = first.Original.Destination
			case "different_reply_destination":
				second.Reply.Destination.Port++
			}
			for _, entries := range [][]Entry{{first, second, first}, {second, first, second}} {
				resolver := newResolver(func() ([]Entry, error) { return entries, nil }, time.Second, time.Now)
				if got, _, ok := resolver.Resolve("tcp", first.Original.Source, first.Original.Destination); ok {
					t.Errorf("ambiguous tuple resolved to %+v", got)
				}
			}
		})
	}
}

func TestResolverInvalidatesOldTableAfterDumpError(t *testing.T) {
	for _, mode := range []string{"scheduled", "miss_refresh"} {
		t.Run(mode, func(t *testing.T) {
			current := time.Unix(100, 0)
			entry := safetyEntry()
			failing := false
			dumps := 0
			resolver := newResolver(func() ([]Entry, error) {
				dumps++
				if failing {
					return nil, errors.New("dump failed")
				}
				return []Entry{entry}, nil
			}, time.Second, func() time.Time { return current })
			if _, _, ok := resolver.Resolve("tcp", entry.Original.Source, entry.Original.Destination); !ok {
				t.Fatal("initial proof missing")
			}
			failing = true
			if mode == "scheduled" {
				current = current.Add(2 * time.Second)
				resolver.Resolve("tcp", entry.Original.Source, entry.Original.Destination)
			} else {
				current = current.Add(30 * time.Millisecond)
				missing := entry.Original.Source
				missing.Port++
				resolver.Resolve("tcp", missing, entry.Original.Destination)
			}
			if _, _, ok := resolver.Resolve("tcp", entry.Original.Source, entry.Original.Destination); ok {
				t.Error("failed dump reused stale backend")
			}
			for i := 0; i < 20; i++ {
				current = current.Add(time.Millisecond)
				resolver.Resolve("tcp", flow.Endpoint{}, flow.Endpoint{})
			}
			if dumps != 2 {
				t.Errorf("failed dump not rate limited: dumps=%d, want 2", dumps)
			}
			failing = false
			current = current.Add(11 * time.Second)
			if _, _, ok := resolver.Resolve("tcp", entry.Original.Source, entry.Original.Destination); !ok {
				t.Error("fresh proof did not recover after backoff")
			}
		})
	}
}

func TestResolverAllowsIdenticalDuplicateEntries(t *testing.T) {
	entry := safetyEntry()
	resolver := newResolver(func() ([]Entry, error) { return []Entry{entry, entry}, nil }, time.Second, time.Now)
	if got, _, ok := resolver.Resolve("tcp", entry.Original.Source, entry.Original.Destination); !ok || got != entry.Reply.Source {
		t.Fatalf("identical duplicates lost proof: %+v %v", got, ok)
	}
}

func TestNewEstablishmentRequiresProofCollectedAfterIt(t *testing.T) {
	current := time.Unix(100, 0)
	entry := safetyEntry()
	resolver := newResolver(func() ([]Entry, error) { return []Entry{entry}, nil }, time.Second, func() time.Time { return current })
	resolver.Resolve("tcp", entry.Original.Source, entry.Original.Destination)
	fresh, ok := any(resolver).(interface {
		ResolveAfter(string, flow.Endpoint, flow.Endpoint, time.Time) (flow.Endpoint, string, bool)
	})
	if !ok {
		t.Fatal("new connections cannot demand fresh kernel proof")
	}
	current = current.Add(5 * time.Millisecond)
	establishedAt := current
	entry.Reply.Source.Address = "10.0.0.99"
	if _, _, ok := fresh.ResolveAfter("tcp", entry.Original.Source, entry.Original.Destination, establishedAt); ok {
		t.Fatal("new socket inherited an older socket's cached backend")
	}
	current = current.Add(30 * time.Millisecond)
	if got, _, ok := fresh.ResolveAfter("tcp", entry.Original.Source, entry.Original.Destination, establishedAt); !ok || got != entry.Reply.Source {
		t.Fatalf("fresh dump did not resolve new socket: %+v %v", got, ok)
	}
}
