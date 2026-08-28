//go:build linux

package collector

import (
	"container/list"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

const defaultSocketResolverCacheEntries = 4096

type socketResolver struct {
	mu         sync.Mutex
	cache      map[processFD]*socketCacheEntry
	recency    *list.List
	maxEntries int
}

type processFD struct {
	pid uint32
	fd  int32
}

type cachedSocket struct {
	inode string
	tuple socketTuple
}

type socketCacheEntry struct {
	value   cachedSocket
	element *list.Element
}

type socketTuple struct {
	family        uint16
	localAddress  [16]byte
	remoteAddress [16]byte
	localPort     uint16
	remotePort    uint16
}

func newSocketResolver() *socketResolver {
	return newSocketResolverWithLimit(defaultSocketResolverCacheEntries)
}

func newSocketResolverWithLimit(maxEntries int) *socketResolver {
	return &socketResolver{
		cache:      make(map[processFD]*socketCacheEntry),
		recency:    list.New(),
		maxEntries: maxEntries,
	}
}

func (resolver *socketResolver) cachedTuple(key processFD, inode string) (socketTuple, bool) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	entry, ok := resolver.cache[key]
	if !ok {
		return socketTuple{}, false
	}
	if entry.value.inode != inode {
		resolver.recency.Remove(entry.element)
		delete(resolver.cache, key)
		return socketTuple{}, false
	}
	resolver.recency.MoveToFront(entry.element)
	return entry.value.tuple, true
}

func (resolver *socketResolver) rememberTuple(key processFD, inode string, tuple socketTuple) {
	if resolver.maxEntries <= 0 {
		return
	}
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	if entry, ok := resolver.cache[key]; ok {
		entry.value = cachedSocket{inode: inode, tuple: tuple}
		resolver.recency.MoveToFront(entry.element)
		return
	}
	element := resolver.recency.PushFront(key)
	resolver.cache[key] = &socketCacheEntry{
		value:   cachedSocket{inode: inode, tuple: tuple},
		element: element,
	}
	if len(resolver.cache) <= resolver.maxEntries {
		return
	}
	oldest := resolver.recency.Back()
	oldestKey := oldest.Value.(processFD)
	resolver.recency.Remove(oldest)
	delete(resolver.cache, oldestKey)
}

func (resolver *socketResolver) enrich(event *Event) error {
	if event == nil {
		return errors.New("event is required")
	}
	key := processFD{pid: event.PID, fd: event.FD}
	linkTarget, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", event.PID, event.FD))
	if err != nil {
		return err
	}
	inode, ok := strings.CutPrefix(linkTarget, "socket:[")
	if !ok || !strings.HasSuffix(inode, "]") {
		return fmt.Errorf("fd is not a socket: %s", linkTarget)
	}
	inode = strings.TrimSuffix(inode, "]")

	tuple, ok := resolver.cachedTuple(key, inode)
	if !ok {
		tuple, err = readProcessSocketTuple(event.PID, inode)
		if err != nil {
			return err
		}
		resolver.rememberTuple(key, inode, tuple)
	}

	event.Family = tuple.family
	event.Protocol = ProtocolTCP
	if event.Direction == DirectionSend {
		event.SourceAddress = tuple.localAddress
		event.DestinationAddress = tuple.remoteAddress
		event.SourcePort = tuple.localPort
		event.DestinationPort = tuple.remotePort
	} else {
		event.SourceAddress = tuple.remoteAddress
		event.DestinationAddress = tuple.localAddress
		event.SourcePort = tuple.remotePort
		event.DestinationPort = tuple.localPort
	}
	return nil
}

func readProcessSocketTuple(pid uint32, inode string) (socketTuple, error) {
	for _, table := range []struct {
		name   string
		family uint16
	}{
		{"tcp", AddressFamilyIPv4},
		{"tcp6", AddressFamilyIPv6},
	} {
		content, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/%s", pid, table.name))
		if err != nil {
			continue
		}
		tuple, ok, err := parseProcNetTCP(string(content), inode, table.family)
		if err != nil {
			return socketTuple{}, fmt.Errorf("parse /proc/%d/net/%s: %w", pid, table.name, err)
		}
		if ok {
			return tuple, nil
		}
	}
	return socketTuple{}, fmt.Errorf("socket inode %s not found in pid %d network namespace", inode, pid)
}

func parseProcNetTCP(content, wantedInode string, family uint16) (socketTuple, bool, error) {
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[9] != wantedInode {
			continue
		}
		localAddress, localPort, err := parseProcEndpoint(fields[1], family)
		if err != nil {
			return socketTuple{}, false, err
		}
		remoteAddress, remotePort, err := parseProcEndpoint(fields[2], family)
		if err != nil {
			return socketTuple{}, false, err
		}
		return socketTuple{
			family:        family,
			localAddress:  localAddress,
			remoteAddress: remoteAddress,
			localPort:     localPort,
			remotePort:    remotePort,
		}, true, nil
	}
	return socketTuple{}, false, nil
}

func parseProcEndpoint(value string, family uint16) ([16]byte, uint16, error) {
	var address [16]byte
	addressHex, portHex, ok := strings.Cut(value, ":")
	if !ok {
		return address, 0, fmt.Errorf("invalid endpoint %q", value)
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return address, 0, fmt.Errorf("parse endpoint port %q: %w", value, err)
	}
	raw, err := hex.DecodeString(addressHex)
	if err != nil {
		return address, 0, fmt.Errorf("parse endpoint address %q: %w", value, err)
	}
	switch family {
	case AddressFamilyIPv4:
		if len(raw) != net.IPv4len {
			return address, 0, fmt.Errorf("IPv4 endpoint %q has %d bytes", value, len(raw))
		}
		for index := range raw {
			address[index] = raw[len(raw)-1-index]
		}
	case AddressFamilyIPv6:
		if len(raw) != net.IPv6len {
			return address, 0, fmt.Errorf("IPv6 endpoint %q has %d bytes", value, len(raw))
		}
		for word := 0; word < 4; word++ {
			for byteIndex := 0; byteIndex < 4; byteIndex++ {
				address[word*4+byteIndex] = raw[word*4+3-byteIndex]
			}
		}
	default:
		return address, 0, fmt.Errorf("unsupported address family %d", family)
	}
	return address, uint16(port), nil
}
