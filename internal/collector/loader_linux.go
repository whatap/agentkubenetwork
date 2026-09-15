//go:build linux

package collector

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const kernelDropPollInterval = time.Second

type openSSLProbe struct {
	symbol      string
	program     *ebpf.Program
	returnProbe bool
}

type openSSLCoverage struct {
	sslSetFD           bool
	sslSetBIO          bool
	sslFree            bool
	bioNewSocketEntry  bool
	bioNewSocketReturn bool
	bioIntCtrl         bool
	bioFree            bool
	sslReadEntry       bool
	sslReadReturn      bool
	sslWriteEntry      bool
	sslWriteReturn     bool
	sslReadExEntry     bool
	sslReadExReturn    bool
	sslWriteExEntry    bool
	sslWriteExReturn   bool
}

func (coverage *openSSLCoverage) record(probe openSSLProbe) {
	switch probe.symbol {
	case "SSL_set_fd":
		coverage.sslSetFD = true
	case "SSL_set_bio":
		coverage.sslSetBIO = true
	case "SSL_free":
		coverage.sslFree = true
	case "BIO_new_socket":
		if probe.returnProbe {
			coverage.bioNewSocketReturn = true
		} else {
			coverage.bioNewSocketEntry = true
		}
	case "BIO_int_ctrl":
		coverage.bioIntCtrl = true
	case "BIO_free":
		coverage.bioFree = true
	case "SSL_read":
		if probe.returnProbe {
			coverage.sslReadReturn = true
		} else {
			coverage.sslReadEntry = true
		}
	case "SSL_write":
		if probe.returnProbe {
			coverage.sslWriteReturn = true
		} else {
			coverage.sslWriteEntry = true
		}
	case "SSL_read_ex":
		if probe.returnProbe {
			coverage.sslReadExReturn = true
		} else {
			coverage.sslReadExEntry = true
		}
	case "SSL_write_ex":
		if probe.returnProbe {
			coverage.sslWriteExReturn = true
		} else {
			coverage.sslWriteExEntry = true
		}
	}
}

func (coverage *openSSLCoverage) merge(other openSSLCoverage) {
	coverage.sslSetFD = coverage.sslSetFD || other.sslSetFD
	coverage.sslSetBIO = coverage.sslSetBIO || other.sslSetBIO
	coverage.sslFree = coverage.sslFree || other.sslFree
	coverage.bioNewSocketEntry = coverage.bioNewSocketEntry || other.bioNewSocketEntry
	coverage.bioNewSocketReturn = coverage.bioNewSocketReturn || other.bioNewSocketReturn
	coverage.bioIntCtrl = coverage.bioIntCtrl || other.bioIntCtrl
	coverage.bioFree = coverage.bioFree || other.bioFree
	coverage.sslReadEntry = coverage.sslReadEntry || other.sslReadEntry
	coverage.sslReadReturn = coverage.sslReadReturn || other.sslReadReturn
	coverage.sslWriteEntry = coverage.sslWriteEntry || other.sslWriteEntry
	coverage.sslWriteReturn = coverage.sslWriteReturn || other.sslWriteReturn
	coverage.sslReadExEntry = coverage.sslReadExEntry || other.sslReadExEntry
	coverage.sslReadExReturn = coverage.sslReadExReturn || other.sslReadExReturn
	coverage.sslWriteExEntry = coverage.sslWriteExEntry || other.sslWriteExEntry
	coverage.sslWriteExReturn = coverage.sslWriteExReturn || other.sslWriteExReturn
}

func (coverage openSSLCoverage) validate() error {
	readPair := (coverage.sslReadEntry && coverage.sslReadReturn) ||
		(coverage.sslReadExEntry && coverage.sslReadExReturn)
	writePair := (coverage.sslWriteEntry && coverage.sslWriteReturn) ||
		(coverage.sslWriteExEntry && coverage.sslWriteExReturn)
	bioMapping := coverage.sslSetBIO &&
		(coverage.bioIntCtrl || (coverage.bioNewSocketEntry && coverage.bioNewSocketReturn))
	var missing []string
	if !readPair {
		missing = append(missing, "read entry/return pair")
	}
	if !writePair {
		missing = append(missing, "write entry/return pair")
	}
	if coverage.sslSetBIO && !bioMapping {
		missing = append(missing, "BIO context-to-fd mapping")
	}
	if !coverage.sslSetFD && !bioMapping {
		missing = append(missing, "context-to-fd mapping")
	}
	if !coverage.sslFree {
		missing = append(missing, "SSL_free lifecycle cleanup")
	}
	if bioMapping && !coverage.bioFree {
		missing = append(missing, "BIO_free lifecycle cleanup")
	}
	if len(missing) > 0 {
		return fmt.Errorf("incomplete OpenSSL probe coverage: missing %s", strings.Join(missing, ", "))
	}
	return nil
}

type bpfReader struct {
	objects          networkObjects
	links            []link.Link
	reader           *ringbuf.Reader
	resolver         *socketResolver
	dropCounters     *ebpf.Map
	dropSnapshot     kernelDropSnapshot
	pending          []Event
	nextDropPollTime time.Time
}

func OpenBPF(optionList ...OpenOptions) (EventReader, error) {
	if len(optionList) > 1 {
		return nil, errors.New("only one OpenOptions value is supported")
	}
	options := OpenOptions{}
	if len(optionList) == 1 {
		options = optionList[0]
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}

	var objects networkObjects
	if err := loadNetworkObjects(&objects, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	links, err := attachKernelPrograms(&objects)
	if err != nil {
		objects.Close()
		return nil, err
	}
	var openSSLCoverage openSSLCoverage
	for _, library := range options.OpenSSLLibraries {
		attached, libraryCoverage, attachErr := attachOpenSSL(&objects, library)
		if attachErr != nil {
			closeLinks(links)
			objects.Close()
			return nil, attachErr
		}
		links = append(links, attached...)
		openSSLCoverage.merge(libraryCoverage)
	}
	if len(options.OpenSSLLibraries) > 0 {
		if err := openSSLCoverage.validate(); err != nil {
			closeLinks(links)
			objects.Close()
			return nil, err
		}
	}

	reader, err := ringbuf.NewReader(objects.Events)
	if err != nil {
		closeLinks(links)
		objects.Close()
		return nil, fmt.Errorf("open BPF ring buffer: %w", err)
	}

	return &bpfReader{
		objects:      objects,
		links:        links,
		reader:       reader,
		resolver:     newSocketResolver(),
		dropCounters: objects.DropCounters,
	}, nil
}

func (reader *bpfReader) Read() (Event, error) {
	for {
		if len(reader.pending) > 0 {
			event := reader.pending[0]
			reader.pending = reader.pending[1:]
			return event, nil
		}
		now := time.Now()
		if reader.nextDropPollTime.IsZero() || !now.Before(reader.nextDropPollTime) {
			if err := reader.pollKernelDrops(); err != nil {
				return Event{}, err
			}
			reader.nextDropPollTime = now.Add(kernelDropPollInterval)
			continue
		}
		reader.reader.SetDeadline(reader.nextDropPollTime)
		record, err := reader.reader.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		if err != nil {
			return Event{}, err
		}
		event, err := decodeEvent(record.RawSample, binary.NativeEndian)
		if err != nil {
			return Event{}, err
		}
		if event.Kind == EventKindL7Fragment && event.Family == 0 {
			event = enrichL7Event(event, reader.resolver)
		}
		return event, nil
	}
}

func (reader *bpfReader) pollKernelDrops() error {
	var current kernelDropSnapshot
	for index := range current {
		key := uint32(index)
		var values []uint64
		if err := reader.dropCounters.Lookup(key, &values); err != nil {
			return fmt.Errorf("read kernel drop counter %d: %w", index, err)
		}
		for _, value := range values {
			current[index] += value
		}
	}
	reader.pending = append(reader.pending, kernelDropEvents(reader.dropSnapshot, current)...)
	reader.dropSnapshot = current
	return nil
}

func (reader *bpfReader) Close() error {
	return errors.Join(
		reader.reader.Close(),
		closeLinks(reader.links),
		reader.objects.Close(),
	)
}

// InterruptRead wakes the event pump without releasing maps or links it may
// still be using. The owner closes those only after the pump has joined.
func (reader *bpfReader) InterruptRead() error {
	return reader.reader.Close()
}

func attachKernelPrograms(objects *networkObjects) ([]link.Link, error) {
	links := make([]link.Link, 0, 12)
	attachTracepoint := func(group, name string, program *ebpf.Program) error {
		attached, err := link.Tracepoint(group, name, program, nil)
		if err != nil {
			return fmt.Errorf("attach %s/%s tracepoint: %w", group, name, err)
		}
		links = append(links, attached)
		return nil
	}
	tracepoints := []struct {
		group   string
		name    string
		program *ebpf.Program
	}{
		{"sock", "inet_sock_set_state", objects.ObserveTcpConnect},
		{"syscalls", "sys_enter_close", objects.ObserveEnterClose},
		{"syscalls", "sys_enter_read", objects.ObserveEnterRead},
		{"syscalls", "sys_exit_read", objects.ObserveExitRead},
		{"syscalls", "sys_enter_write", objects.ObserveEnterWrite},
		{"syscalls", "sys_exit_write", objects.ObserveExitWrite},
		{"syscalls", "sys_enter_recvfrom", objects.ObserveEnterRecvfrom},
		{"syscalls", "sys_exit_recvfrom", objects.ObserveExitRecvfrom},
		{"syscalls", "sys_enter_sendto", objects.ObserveEnterSendto},
		{"syscalls", "sys_exit_sendto", objects.ObserveExitSendto},
	}
	for _, tracepoint := range tracepoints {
		if err := attachTracepoint(tracepoint.group, tracepoint.name, tracepoint.program); err != nil {
			closeLinks(links)
			return nil, err
		}
	}
	for name, program := range map[string]*ebpf.Program{
		"tcp_sendmsg": objects.ObserveTcpSendmsg,
		"tcp_recvmsg": objects.ObserveTcpRecvmsg,
		"udp_sendmsg": objects.ObserveUdpSendmsg,
		"udp_recvmsg": objects.ObserveUdpRecvmsg,
	} {
		attached, err := link.AttachTracing(link.TracingOptions{Program: program})
		if err != nil {
			closeLinks(links)
			return nil, fmt.Errorf("attach %s fentry: %w", name, err)
		}
		links = append(links, attached)
	}
	return links, nil
}

func attachOpenSSL(objects *networkObjects, path string) ([]link.Link, openSSLCoverage, error) {
	definedSymbols, err := definedELFSymbols(path)
	if err != nil {
		return nil, openSSLCoverage{}, fmt.Errorf("read OpenSSL symbols from %q: %w", path, err)
	}
	executable, err := link.OpenExecutable(path)
	if err != nil {
		return nil, openSSLCoverage{}, fmt.Errorf("open OpenSSL library %q: %w", path, err)
	}
	var probes []openSSLProbe
	switch runtime.GOARCH {
	case "amd64":
		probes = []openSSLProbe{
			{"SSL_set_fd", objects.ObserveSslSetFdX86, false},
			{"BIO_new_socket", objects.ObserveBioNewSocketX86, false},
			{"BIO_new_socket", objects.ObserveBioNewSocketReturnX86, true},
			{"BIO_int_ctrl", objects.ObserveBioIntCtrlX86, false},
			{"SSL_set_bio", objects.ObserveSslSetBioX86, false},
			{"BIO_free", objects.ObserveBioFreeX86, false},
			{"SSL_free", objects.ObserveSslFreeX86, false},
			{"SSL_read", objects.ObserveSslReadX86, false},
			{"SSL_read", objects.ObserveSslReadReturnX86, true},
			{"SSL_write", objects.ObserveSslWriteX86, false},
			{"SSL_write", objects.ObserveSslWriteReturnX86, true},
			{"SSL_read_ex", objects.ObserveSslReadExX86, false},
			{"SSL_read_ex", objects.ObserveSslReadExReturnX86, true},
			{"SSL_write_ex", objects.ObserveSslWriteExX86, false},
			{"SSL_write_ex", objects.ObserveSslWriteExReturnX86, true},
		}
	case "arm64":
		probes = []openSSLProbe{
			{"SSL_set_fd", objects.ObserveSslSetFdArm64, false},
			{"BIO_new_socket", objects.ObserveBioNewSocketArm64, false},
			{"BIO_new_socket", objects.ObserveBioNewSocketReturnArm64, true},
			{"BIO_int_ctrl", objects.ObserveBioIntCtrlArm64, false},
			{"SSL_set_bio", objects.ObserveSslSetBioArm64, false},
			{"BIO_free", objects.ObserveBioFreeArm64, false},
			{"SSL_free", objects.ObserveSslFreeArm64, false},
			{"SSL_read", objects.ObserveSslReadArm64, false},
			{"SSL_read", objects.ObserveSslReadReturnArm64, true},
			{"SSL_write", objects.ObserveSslWriteArm64, false},
			{"SSL_write", objects.ObserveSslWriteReturnArm64, true},
			{"SSL_read_ex", objects.ObserveSslReadExArm64, false},
			{"SSL_read_ex", objects.ObserveSslReadExReturnArm64, true},
			{"SSL_write_ex", objects.ObserveSslWriteExArm64, false},
			{"SSL_write_ex", objects.ObserveSslWriteExReturnArm64, true},
		}
	default:
		return nil, openSSLCoverage{}, fmt.Errorf("OpenSSL uprobes do not support architecture %s", runtime.GOARCH)
	}

	links := make([]link.Link, 0, len(probes))
	var coverage openSSLCoverage
	for _, probe := range probes {
		if _, defined := definedSymbols[probe.symbol]; !defined {
			continue
		}
		var attached link.Link
		if probe.returnProbe {
			attached, err = executable.Uretprobe(probe.symbol, probe.program, nil)
		} else {
			attached, err = executable.Uprobe(probe.symbol, probe.program, nil)
		}
		if err != nil {
			closeLinks(links)
			return nil, openSSLCoverage{}, fmt.Errorf("attach %s in OpenSSL library %q: %w", probe.symbol, path, err)
		}
		links = append(links, attached)
		coverage.record(probe)
	}
	if len(links) == 0 {
		return nil, openSSLCoverage{}, fmt.Errorf("OpenSSL library %q has none of the supported SSL/BIO symbols", path)
	}
	return links, coverage, nil
}

func definedELFSymbols(path string) (map[string]struct{}, error) {
	file, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	symbols, err := file.DynamicSymbols()
	if err != nil {
		return nil, err
	}
	return definedELFSymbolSet(symbols), nil
}

func definedELFSymbolSet(symbols []elf.Symbol) map[string]struct{} {
	defined := make(map[string]struct{}, len(symbols))
	for _, symbol := range symbols {
		if symbol.Section != elf.SHN_UNDEF {
			defined[symbol.Name] = struct{}{}
		}
	}
	return defined
}

func closeLinks(links []link.Link) error {
	errorsToJoin := make([]error, 0, len(links))
	for index := len(links) - 1; index >= 0; index-- {
		errorsToJoin = append(errorsToJoin, links[index].Close())
	}
	return errors.Join(errorsToJoin...)
}
