//go:build linux

package collector

import (
	"debug/elf"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

func TestNetworkObjectCarriesCORERelocationsForTracepointContext(t *testing.T) {
	spec, err := loadNetwork()
	if err != nil {
		t.Fatalf("load embedded BPF collection: %v", err)
	}

	program := spec.Programs["observe_tcp_connect"]
	if program == nil {
		t.Fatal("embedded BPF collection has no observe_tcp_connect program")
	}

	var relocationCount int
	var hasTracepointContextRelocation bool
	iterator := program.Instructions.Iterate()
	for iterator.Next() {
		relocation := btf.CORERelocationMetadata(iterator.Ins)
		if relocation == nil {
			continue
		}
		relocationCount++
		if strings.Contains(relocation.String(), "trace_event_raw_inet_sock_set_state") {
			hasTracepointContextRelocation = true
		}
	}

	if relocationCount == 0 {
		t.Fatal("observe_tcp_connect has no CO-RE relocations; tracepoint field offsets are fixed at compile time")
	}
	if !hasTracepointContextRelocation {
		t.Fatalf("observe_tcp_connect has %d CO-RE relocations, none for trace_event_raw_inet_sock_set_state", relocationCount)
	}
}

func TestEmbeddedNetworkObjectMatchesCurrentCollectorSurface(t *testing.T) {
	spec, err := loadNetwork()
	if err != nil {
		t.Fatalf("load embedded BPF collection: %v", err)
	}
	for _, name := range []string{
		"observe_tcp_connect",
		"observe_enter_close",
		"observe_enter_read",
		"observe_exit_read",
		"observe_enter_write",
		"observe_exit_write",
		"observe_enter_recvfrom",
		"observe_exit_recvfrom",
		"observe_enter_sendto",
		"observe_exit_sendto",
		"observe_tcp_sendmsg",
		"observe_tcp_recvmsg",
		"observe_ssl_set_fd_x86",
		"observe_ssl_set_fd_arm64",
		"observe_bio_new_socket_x86",
		"observe_bio_new_socket_arm64",
		"observe_bio_new_socket_return_x86",
		"observe_bio_new_socket_return_arm64",
		"observe_bio_int_ctrl_x86",
		"observe_bio_int_ctrl_arm64",
		"observe_ssl_set_bio_x86",
		"observe_ssl_set_bio_arm64",
		"observe_bio_free_x86",
		"observe_bio_free_arm64",
		"observe_ssl_free_x86",
		"observe_ssl_free_arm64",
		"observe_ssl_read_x86",
		"observe_ssl_read_arm64",
		"observe_ssl_read_return_x86",
		"observe_ssl_read_return_arm64",
		"observe_ssl_write_x86",
		"observe_ssl_write_arm64",
		"observe_ssl_write_return_x86",
		"observe_ssl_write_return_arm64",
		"observe_ssl_read_ex_x86",
		"observe_ssl_read_ex_arm64",
		"observe_ssl_read_ex_return_x86",
		"observe_ssl_read_ex_return_arm64",
		"observe_ssl_write_ex_x86",
		"observe_ssl_write_ex_arm64",
		"observe_ssl_write_ex_return_x86",
		"observe_ssl_write_ex_return_arm64",
	} {
		if spec.Programs[name] == nil {
			t.Errorf("embedded BPF object is missing program %q; run make generate-ebpf", name)
		}
	}
	for _, name := range []string{
		"io_calls",
		"ssl_fds",
		"bio_new_socket_calls",
		"bio_fds",
		"http2_connections",
		"ssl_read_calls",
		"ssl_write_calls",
		"ssl_read_ex_calls",
		"ssl_write_ex_calls",
		"srtt_samples",
	} {
		mapSpec := spec.Maps[name]
		if mapSpec == nil {
			t.Errorf("embedded BPF object is missing map %q; run make generate-ebpf", name)
			continue
		}
		if mapSpec.Type != ebpf.LRUHash {
			t.Errorf("map %q type = %s, want LRUHash", name, mapSpec.Type)
		}
	}
	events := spec.Maps["events"]
	if events == nil {
		t.Fatal("embedded BPF object is missing events map; run make generate-ebpf")
	}
	if events.Type != ebpf.RingBuf {
		t.Errorf("events map type = %s, want RingBuf", events.Type)
	}
	dropCounters := spec.Maps["drop_counters"]
	if dropCounters == nil {
		t.Fatal("embedded BPF object is missing drop_counters map; run make generate")
	}
	if dropCounters.Type != ebpf.PerCPUArray || dropCounters.MaxEntries != kernelDropReasonCount {
		t.Errorf("drop_counters = {type:%s max_entries:%d}, want {PerCPUArray %d}", dropCounters.Type, dropCounters.MaxEntries, kernelDropReasonCount)
	}
}

func TestOpenSSLCoverageValidation(t *testing.T) {
	completeDirect := openSSLCoverage{
		sslSetFD:       true,
		sslReadEntry:   true,
		sslReadReturn:  true,
		sslWriteEntry:  true,
		sslWriteReturn: true,
	}
	completeDirect.record(openSSLProbe{symbol: "SSL_free"})
	if err := completeDirect.validate(); err != nil {
		t.Fatalf("direct fd coverage rejected: %v", err)
	}
	completeBIO := openSSLCoverage{
		sslSetBIO:        true,
		bioIntCtrl:       true,
		sslReadExEntry:   true,
		sslReadExReturn:  true,
		sslWriteExEntry:  true,
		sslWriteExReturn: true,
	}
	completeBIO.record(openSSLProbe{symbol: "SSL_free"})
	completeBIO.record(openSSLProbe{symbol: "BIO_free"})
	if err := completeBIO.validate(); err != nil {
		t.Fatalf("BIO coverage rejected: %v", err)
	}

	missingMapping := completeDirect
	missingMapping.sslSetFD = false
	if err := missingMapping.validate(); err == nil || !strings.Contains(err.Error(), "context-to-fd") {
		t.Fatalf("missing mapping validation error = %v", err)
	}
	missingReturn := completeDirect
	missingReturn.sslReadReturn = false
	if err := missingReturn.validate(); err == nil || !strings.Contains(err.Error(), "read entry/return pair") {
		t.Fatalf("missing return validation error = %v", err)
	}
}

func TestOpenSSLCoverageValidationRejectsPartialBIOAndMissingCleanup(t *testing.T) {
	direct := openSSLCoverage{
		sslSetFD:       true,
		sslReadEntry:   true,
		sslReadReturn:  true,
		sslWriteEntry:  true,
		sslWriteReturn: true,
	}
	if err := direct.validate(); err == nil || !strings.Contains(err.Error(), "SSL_free") {
		t.Fatalf("missing SSL_free validation error = %v", err)
	}
	direct.record(openSSLProbe{symbol: "SSL_free"})
	direct.sslSetBIO = true
	if err := direct.validate(); err == nil || !strings.Contains(err.Error(), "BIO context-to-fd") {
		t.Fatalf("partial BIO validation error = %v", err)
	}

	bio := openSSLCoverage{
		sslSetBIO:        true,
		bioIntCtrl:       true,
		sslReadExEntry:   true,
		sslReadExReturn:  true,
		sslWriteExEntry:  true,
		sslWriteExReturn: true,
	}
	bio.record(openSSLProbe{symbol: "SSL_free"})
	if err := bio.validate(); err == nil || !strings.Contains(err.Error(), "BIO_free") {
		t.Fatalf("missing BIO_free validation error = %v", err)
	}
	bio.record(openSSLProbe{symbol: "BIO_free"})
	if err := bio.validate(); err != nil {
		t.Fatalf("complete BIO lifecycle rejected: %v", err)
	}
}

func TestDefinedELFSymbolSetSkipsUndefinedImports(t *testing.T) {
	symbols := []elf.Symbol{
		{Name: "BIO_int_ctrl", Section: elf.SHN_UNDEF},
		{Name: "SSL_read", Section: elf.SectionIndex(12)},
		{Name: "SSL_write", Section: elf.SHN_ABS},
	}
	defined := definedELFSymbolSet(symbols)
	if _, exists := defined["BIO_int_ctrl"]; exists {
		t.Fatal("undefined import BIO_int_ctrl was classified as an implementation target")
	}
	for _, name := range []string{"SSL_read", "SSL_write"} {
		if _, exists := defined[name]; !exists {
			t.Errorf("defined symbol %q was omitted", name)
		}
	}
}
