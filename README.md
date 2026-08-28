# agentkubenetwork

`agentkubenetwork` is a new Kubernetes node network-observability collector. It is a clean implementation informed by the retired `whatap/npmagent` codebase; it is not a continuation of the retired npmAgent service.

## Status

Pre-alpha passive-observation vertical slice. The current boundaries are:

```text
sock:inet_sock_set_state tracepoint
  -> successful outbound TCP-connect ring-buffer event
  -> typed Event -> normalized Observation

tcp_sendmsg/tcp_recvmsg fentry
  -> tcp_sock.srtt_us >> 3 and mdev_us >> 2
  -> canonical connection-level RTT/jitter evidence

read/write/recvfrom/sendto tracepoints + supported OpenSSL uprobes
  -> bounded plaintext protocol prefixes
  -> conservative HTTP/1 and HTTP/2 request/response correlation

normalized flow observations (JSONL)
  -> deterministic 5-second EdgeWindow aggregation
  -> versioned window records (JSONL)

L7 transactions and coverage drops
  -> network.l7/v1alpha1 JSONL
```

The eBPF source, Linux object generation, loader, attach, and ring-buffer decode path have been verified on both the `okd-k8s` manager host and a standalone Pod on one OKD worker. CO-RE relocations keep tracepoint field reads compatible when the worker kernel adds fields to the common trace entry. This validates the current connect tracer bullet, not production DaemonSet packaging or least-privilege SCC policy. Timing statistics keep `count/sum/min/max` rather than repeatedly averaging averages, preventing the order-dependent merge defect found in the legacy implementation.

## Run

```bash
make check

go run ./cmd/agentkubenetwork \
  -window 5s \
  < testdata/observations.jsonl
```

The default command reads one `flow.Observation` JSON object per line from standard input and writes one `network.flow/v1alpha1` window per line to standard output. On a supported Linux host, the passive collector runs with:

```bash
sudo ./agentkubenetwork \
  -source ebpf \
  -node-name "$NODE_NAME" \
  -openssl-library /lib/x86_64-linux-gnu/libssl.so.3,/lib/x86_64-linux-gnu/libcrypto.so.3
```

OpenSSL libraries are opt-in and platform-specific. Both paths are needed on OpenSSL 3 systems that split SSL APIs into `libssl` and BIO APIs into `libcrypto`.

## eBPF source

```text
internal/collector/bpf/flow.bpf.c   tracepoint program and ring-buffer ABI
internal/collector/loader_linux.go  cilium/ebpf load, attach, and read path
internal/collector/wire.go          fixed 360-byte event decoder
internal/collector/event.go         Event -> Observation semantics
```

`make check` runs a BPF-target C syntax check on macOS and all Go tests. On Linux, generate the embedded object before the full build:

```bash
make generate-ebpf
make check
```

CI regenerates the checked-in eBPF artifacts and fails if either artifact changes. The embedded-object Linux test also requires every loader-referenced program and map and verifies bounded map types, preventing a stale or incomplete object from silently reaching runtime.

### SRTT and L7 evidence contract

- TCP SRTT uses Linux `tcp_sock.srtt_us >> 3`; RTT variance uses `mdev_us >> 2`. Send and receive samples are normalized into one canonical connection key.
- SRTT and L7 duration are independent evidence. The collector does **not** calculate `request_duration - SRTT` as application time.
- HTTP latency is `request_to_response_headers`, not full body duration. Query strings are removed and plaintext payload bytes are never written to JSONL.
- HTTP/1 correlates one non-overlapping request per normalized connection. Informational `1xx` responses do not consume the request. Detected pipelining/overlap and `101` upgrades emit coverage drops instead of guessed transactions.
- HTTP/2 correlates `(normalized connection, stream ID)`, maintains direction-specific HPACK state, and supports HEADERS/CONTINUATION. A known kernel truncation or frame/HPACK decode failure poisons that direction and emits `http2_stream_desync`; later frames are not guessed.
- OpenSSL support observes plaintext buffers passed to supported SSL APIs. It does not decrypt TLS records. Context-to-fd mapping covers `SSL_set_fd`, `BIO_new_socket`, `BIO_int_ctrl(BIO_C_SET_FD)`, and `SSL_set_bio` lifecycles.
- Correlator state expires after 30 seconds and is swept every 256 fragments. Defaults cap tracked connections at 16,384, pending HTTP/2 streams at 65,536, and the `/proc` socket resolver LRU at 4,096 entries.
- Ring-buffer reserve/output and payload-read failures are counted in a per-CPU BPF map and emitted as coverage drops with a delta `count`. A missing L7 transaction is never represented as `0ms`.

This is aggregate evidence, not full TCP stream reconstruction or APM-level tracing. Current syscall plaintext coverage excludes `readv/writev`, `sendmsg/recvmsg`, io_uring, sendfile, and kTLS. HTTP/2 correctness is fail-closed when loss or truncation is detectable; undetectable skipped syscall paths remain a declared coverage gap. Kernel tracing currently requires the tracepoints, BTF/CO-RE support, and fentry attachment used by the object; there is no automatic lower-capability fallback yet.

### Verified Linux and OKD tracer bullet

On 2026-08-18, Ubuntu 24.04 / Linux 6.17.0 x86_64 on `okd-k8s` generated the BPF object, built the binary, attached `observe_tcp_connect` to tracepoint ID 1706, and captured one controlled loopback connection:

```text
127.0.0.1:<ephemeral> -> 127.0.0.1:22
protocol=tcp direction=egress events=1
```

The process exited after one event and `bpftool` confirmed the program was unloaded.

On 2026-08-24, the same embedded object ran in a standalone privileged canary Pod on `worker01.okd4.cluster.local` (RHCOS / Linux 5.14 x86_64). That kernel's trace entry includes `common_preempt_lazy_count`, shifting all payload fields by eight bytes relative to the manager kernel. The probe uses BTF-backed CO-RE field relocations plus `bpf_probe_read_kernel`, so the worker emitted correctly decoded Pod egress tuples without a kernel-specific object:

```text
canary Pod TCP connect
  -> worker sock:inet_sock_set_state
  -> CO-RE-relocated eBPF program
  -> ring buffer
  -> Go Event -> Observation JSONL
```

The controlled run completed with 300 successful trigger requests, 200 decoded events, and 167 exact canary tuples in the bounded capture. The canary Pod exited successfully, and follow-up BPF syscalls confirmed its link, program, and map IDs were all absent. Evidence remains under `/home/ubuntu/jykim/ebpf-test/evidence/`. Reusable image-based deployment, measured least privilege, and DaemonSet validation remain separate gates.

## Intended deployment

Development starts as a one-node canary DaemonSet for kernel, BTF, capability, and resource validation. Once stable, the intended default packaging is a managed third container in the existing `whatap-node-agent` DaemonSet:

```text
whatap-node-agent Pod
├─ whatap-node-agent       (agentkubejava)
├─ whatap-node-helper      (agentkubego)
└─ whatap-network-agent    (this repository)
```

Customers requiring a separate OpenShift SCC or independent rollout can retain a standalone DaemonSet mode.

## Porting policy

Do not copy the npmAgent repository wholesale. Port one kernel hook and one field contract at a time, with a failing test and a Linux integration fixture first. See:

- [`docs/architecture.md`](docs/architecture.md)
- [`docs/npmagent-porting-map.md`](docs/npmagent-porting-map.md)

## Not implemented yet

- release policy for generated eBPF objects and immutable Linux artifacts
- immutable image-based OKD deployment and DaemonSet rollout verification
- inbound/close/reset TCP lifecycle observations
- bytes, packets, retransmission, loss, and UDP observations
- vectored I/O, io_uring, sendfile, kTLS, non-OpenSSL TLS libraries, and complete TCP stream reconstruction
- Kubernetes Pod/Service/Workload identity
- WhaTap backend transport
- reusable OpenShift manifests and measured least-privilege SCC
- long-duration pressure/churn qualification and production alerting for coverage/drop counters

## License

TBD by WhaTap Labs before external distribution.
