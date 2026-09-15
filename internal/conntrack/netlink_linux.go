//go:build linux

package conntrack

import (
	"encoding/binary"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

const (
	nfnlSubsysCtnetlink = 1
	ipctnlMsgCtGet      = 1
	nfnetlinkV0         = 0
)

// NewNetlinkResolver returns a Resolver backed by ctnetlink dumps of the
// kernel conntrack table. ttl bounds how often the table is re-dumped.
func NewNetlinkResolver(ttl time.Duration) *Resolver {
	return newResolver(dumpNetlink, ttl, time.Now)
}

func dumpNetlink() ([]Entry, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("open netfilter netlink socket: %w", err)
	}
	defer unix.Close(fd)
	address := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(fd, address); err != nil {
		return nil, fmt.Errorf("bind netfilter netlink socket: %w", err)
	}
	if err := unix.Sendto(fd, dumpRequest(), 0, address); err != nil {
		return nil, fmt.Errorf("send conntrack dump request: %w", err)
	}

	buffer := make([]byte, 1<<16)
	var entries []Entry
	for {
		length, _, err := unix.Recvfrom(fd, buffer, 0)
		if err != nil {
			return nil, fmt.Errorf("receive conntrack dump: %w", err)
		}
		parsed, done, err := parseMessages(buffer[:length])
		if err != nil {
			return nil, err
		}
		entries = append(entries, parsed...)
		if done {
			return entries, nil
		}
	}
}

func dumpRequest() []byte {
	request := make([]byte, nlmsgHeaderLength+nfgenmsgLength)
	binary.NativeEndian.PutUint32(request[0:4], uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:6], nfnlSubsysCtnetlink<<8|ipctnlMsgCtGet)
	binary.NativeEndian.PutUint16(request[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(request[8:12], 1)  // sequence
	binary.NativeEndian.PutUint32(request[12:16], 0) // port id
	request[16] = unix.AF_UNSPEC                     // nfgenmsg family: all
	request[17] = nfnetlinkV0
	return request
}
