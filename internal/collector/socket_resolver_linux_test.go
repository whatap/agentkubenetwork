//go:build linux

package collector

import (
	"net"
	"testing"
)

func TestParseProcNetTCPIPv4(t *testing.T) {
	content := "  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n" +
		"   0: 0100007F:1F90 0200007F:C350 01 00000000:00000000 00:00000000 00000000 1000 0 12345 1\n"
	tuple, ok, err := parseProcNetTCP(content, "12345", AddressFamilyIPv4)
	if err != nil || !ok {
		t.Fatalf("parseProcNetTCP = (%+v, %v, %v)", tuple, ok, err)
	}
	if got := net.IP(tuple.localAddress[:4]).String(); got != "127.0.0.1" {
		t.Fatalf("local address = %s", got)
	}
	if got := net.IP(tuple.remoteAddress[:4]).String(); got != "127.0.0.2" {
		t.Fatalf("remote address = %s", got)
	}
	if tuple.localPort != 8080 || tuple.remotePort != 50000 {
		t.Fatalf("ports = %d -> %d", tuple.localPort, tuple.remotePort)
	}
}

func TestParseProcEndpointIPv6Loopback(t *testing.T) {
	address, port, err := parseProcEndpoint("00000000000000000000000001000000:20FB", AddressFamilyIPv6)
	if err != nil {
		t.Fatalf("parseProcEndpoint returned error: %v", err)
	}
	if got := net.IP(address[:]).String(); got != "::1" {
		t.Fatalf("address = %s", got)
	}
	if port != 8443 {
		t.Fatalf("port = %d", port)
	}
}

func TestSocketResolverCacheIsBoundedLRU(t *testing.T) {
	resolver := newSocketResolverWithLimit(2)
	first := processFD{pid: 1, fd: 10}
	second := processFD{pid: 2, fd: 20}
	third := processFD{pid: 3, fd: 30}
	resolver.rememberTuple(first, "100", socketTuple{localPort: 100})
	resolver.rememberTuple(second, "200", socketTuple{localPort: 200})
	if _, ok := resolver.cachedTuple(first, "100"); !ok {
		t.Fatal("first cache entry was not found")
	}
	resolver.rememberTuple(third, "300", socketTuple{localPort: 300})

	if _, ok := resolver.cachedTuple(second, "200"); ok {
		t.Fatal("least-recently-used cache entry was not evicted")
	}
	if tuple, ok := resolver.cachedTuple(first, "100"); !ok || tuple.localPort != 100 {
		t.Fatalf("recent cache entry = (%+v, %v)", tuple, ok)
	}
	if tuple, ok := resolver.cachedTuple(third, "300"); !ok || tuple.localPort != 300 {
		t.Fatalf("new cache entry = (%+v, %v)", tuple, ok)
	}
	if len(resolver.cache) != 2 {
		t.Fatalf("cache size = %d, want 2", len(resolver.cache))
	}
}
