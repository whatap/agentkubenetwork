package collector

import (
	"errors"
)

var ErrUnsupportedPlatform = errors.New("eBPF collector is supported only on Linux")

type OpenOptions struct {
	OpenSSLLibraries []string
}

type EventReader interface {
	Read() (Event, error)
	Close() error
}
