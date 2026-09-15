// Package process resolves kernel-reported host PIDs into process identity
// (comm, cmdline, start time, container ID) by reading procfs. The kernel PID
// alone is ambiguous once a process exits and the PID is reused, so the
// /proc/<pid>/stat start time is captured alongside every lookup and cached
// entries are only reused while that start time still matches.
package process

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
)

const (
	// Via is recorded on every resolved process so consumers know the
	// identity came from procfs rather than from the kernel event itself.
	Via = "procfs"

	defaultTTL        = 30 * time.Second
	defaultMaxCmdline = 512
	defaultMaxEntries = 8192
)

// containerIDPattern matches the 64-hex container ID that container runtimes
// (containerd/CRI-O/Docker) embed in cgroup paths, e.g.
// ".../cri-containerd-<id>.scope", ".../crio-<id>.scope", ".../docker/<id>".
var containerIDPattern = regexp.MustCompile(`(?:^|[/-])([0-9a-f]{64})(?:\.scope)?$`)

type entry struct {
	process   flow.Process
	expiresAt time.Time
}

// Resolver reads process identity from a procfs root and caches it per PID.
type Resolver struct {
	root       string
	ttl        time.Duration
	maxCmdline int
	maxEntries int
	now        func() time.Time

	mu    sync.Mutex
	cache map[uint32]entry
}

// Option customises a Resolver.
type Option func(*Resolver)

// WithTTL bounds how long a resolved identity is reused before /proc is
// re-read to confirm the PID still belongs to the same process.
func WithTTL(ttl time.Duration) Option {
	return func(resolver *Resolver) {
		if ttl > 0 {
			resolver.ttl = ttl
		}
	}
}

// WithMaxCmdline truncates the reported cmdline to at most n bytes.
func WithMaxCmdline(n int) Option {
	return func(resolver *Resolver) {
		if n > 0 {
			resolver.maxCmdline = n
		}
	}
}

func withClock(now func() time.Time) Option {
	return func(resolver *Resolver) {
		if now != nil {
			resolver.now = now
		}
	}
}

// NewResolver returns a Resolver reading from the given procfs root
// (normally "/proc"; a host mount such as "/host/proc" inside a container).
func NewResolver(root string, options ...Option) *Resolver {
	if root == "" {
		root = "/proc"
	}
	resolver := &Resolver{
		root:       root,
		ttl:        defaultTTL,
		maxCmdline: defaultMaxCmdline,
		maxEntries: defaultMaxEntries,
		now:        time.Now,
		cache:      make(map[uint32]entry),
	}
	for _, option := range options {
		option(resolver)
	}
	return resolver
}

// Lookup resolves pid. It returns false when pid is zero (kernel context with
// no owning task) or when /proc/<pid> cannot be read, so callers can keep the
// bare kernel PID without inventing identity.
func (resolver *Resolver) Lookup(pid uint32) (flow.Process, bool) {
	if pid == 0 {
		return flow.Process{}, false
	}
	now := resolver.now()

	resolver.mu.Lock()
	cached, ok := resolver.cache[pid]
	resolver.mu.Unlock()
	if ok && now.Before(cached.expiresAt) {
		return cached.process, true
	}

	process, err := readProcess(resolver.root, pid, resolver.maxCmdline)
	if err != nil {
		resolver.mu.Lock()
		delete(resolver.cache, pid)
		resolver.mu.Unlock()
		return flow.Process{}, false
	}
	// A start-time mismatch against the expired cache entry means the PID was
	// reused by a different process; the fresh read simply replaces it.
	resolver.mu.Lock()
	if len(resolver.cache) >= resolver.maxEntries {
		resolver.evictExpiredLocked(now)
	}
	if len(resolver.cache) < resolver.maxEntries {
		resolver.cache[pid] = entry{process: process, expiresAt: now.Add(resolver.ttl)}
	}
	resolver.mu.Unlock()
	return process, true
}

func (resolver *Resolver) evictExpiredLocked(now time.Time) {
	for pid, cached := range resolver.cache {
		if !now.Before(cached.expiresAt) {
			delete(resolver.cache, pid)
		}
	}
}

func readProcess(root string, pid uint32, maxCmdline int) (flow.Process, error) {
	dir := filepath.Join(root, strconv.FormatUint(uint64(pid), 10))
	stat, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return flow.Process{}, err
	}
	comm, startTime, err := parseStat(stat)
	if err != nil {
		return flow.Process{}, fmt.Errorf("parse %s/stat: %w", dir, err)
	}
	process := flow.Process{
		PID:            pid,
		StartTimeTicks: startTime,
		Comm:           comm,
		Via:            Via,
	}
	if cmdline, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
		process.Cmdline = formatCmdline(cmdline, maxCmdline)
	}
	if cgroup, err := os.ReadFile(filepath.Join(dir, "cgroup")); err == nil {
		process.ContainerID = ParseContainerID(string(cgroup))
	}
	return process, nil
}

// parseStat extracts comm (field 2, parenthesised, may contain spaces) and
// starttime (field 22, clock ticks since boot) from /proc/<pid>/stat.
func parseStat(stat []byte) (string, uint64, error) {
	open := bytes.IndexByte(stat, '(')
	close := bytes.LastIndexByte(stat, ')')
	if open < 0 || close < 0 || close < open {
		return "", 0, errors.New("comm field not found")
	}
	comm := string(stat[open+1 : close])
	fields := strings.Fields(string(stat[close+1:]))
	// fields[0] is field 3 (state); starttime is field 22 → index 19.
	if len(fields) < 20 {
		return "", 0, errors.New("starttime field not found")
	}
	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return "", 0, fmt.Errorf("starttime: %w", err)
	}
	return comm, startTime, nil
}

func formatCmdline(raw []byte, limit int) string {
	raw = bytes.TrimRight(raw, "\x00")
	text := strings.ReplaceAll(string(raw), "\x00", " ")
	if limit > 0 && len(text) > limit {
		text = text[:limit]
	}
	return text
}

// ParseContainerID returns the container ID found in a /proc/<pid>/cgroup
// listing, or "" when the process is not inside a recognised container
// cgroup. Both cgroup v2 ("0::/path") and v1 ("N:controllers:/path") lines are
// scanned; the first match wins.
func ParseContainerID(cgroup string) string {
	for _, line := range strings.Split(cgroup, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		path := parts[2]
		for _, segment := range strings.Split(path, "/") {
			if match := containerIDPattern.FindStringSubmatch(segment); match != nil {
				return match[1]
			}
		}
	}
	return ""
}
