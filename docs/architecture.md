# Architecture

## Product direction

The base collector is node-level eBPF plus Kubernetes identity. Istio is not a prerequisite. APM data is correlated later for request and user impact; generic TCP RTT is not presented as application response time.

## Runtime shape

```text
Linux kernel
  -> eBPF probes/maps
  -> collector poller
  -> normalized Observation -> 5-second EdgeWindow
  -> conservative L7 transaction / coverage drop
  -> queue/sender
  -> WhaTap backend
  -> query/API/UI
```

The first committed boundary is `Observation -> EdgeWindow`. Kernel and transport adapters must feed and consume this contract rather than embedding aggregation logic in probe-specific code.

## Data rules

1. Windows are half-open intervals: `[windowStart, windowEnd)`.
2. Timing values use integer microseconds in the collector.
3. Mergeable timing state is `count/sum/min/max`; average is derived as `sum/count`.
4. Source and destination orientation follows connection semantics, not the observing node's arbitrary local/foreign labels.
5. Every future record carries provenance and quality metadata for partial/dropped observations.
6. Pod IP is not a durable identity. Pod UID, workload UID, Service UID, cgroup/container identity, and valid time are added before topology is considered complete.
7. SRTT and L7 request duration remain separate evidence; subtracting one from the other is not a valid application-time calculation.

## Delivery phases

### Phase 0 — contract tracer bullet (current)

- JSONL observations
- deterministic 5-second windows
- order-independent timing merge
- executable CLI and tests

### Phase 1 — Linux eBPF vertical slice (in progress)

- self-contained `sock:inet_sock_set_state` tracepoint source for successful outbound connects
- cilium/ebpf ring-buffer loader and fixed 360-byte wire decoder
- canonical connection-level TCP SRTT/jitter sampling from `tcp_sock`
- conservative HTTP/1, HTTP/2/HPACK, and supported OpenSSL plaintext-buffer correlation
- bounded userspace/BPF state, fail-closed HTTP/2 desynchronization, and explicit coverage/drop counters
- Linux object generation and live attach verified on the `okd-k8s` manager host and a standalone Pod on one OKD worker
- BTF-backed CO-RE tracepoint reads verified across manager Linux 6.17 and worker Linux 5.14 layouts
- controlled TCP, HTTP/1 `100 Continue`, concurrent h2c streams, and OpenSSL HTTPS flows decoded from the manager ring buffer
- reusable immutable-image canary and least-privilege SCC measurement remain
- then bytes, packets, retransmission, and loss into an `Observation`
- network-namespace and long-duration churn/pressure integration tests

### Phase 2 — connection evidence

Add one behavior at a time:

1. connection attempt/success/error
2. reset
3. retransmission
4. loss
5. timeout event (kept separate from an RTO estimate)
6. UDP flow

### Phase 3 — Kubernetes identity

- node identity from Downward API
- cgroup/container -> Pod UID
- Pod -> owner Workload UID
- Service/EndpointSlice identity
- original and translated tuple
- valid-from/valid-to mapping

### Phase 4 — backend tracer bullet

Send one versioned window through the real generic pack/ingest path and read it back via query/API before building the final UI.

### Phase 5 — operator packaging

- one-node standalone canary DaemonSet first
- measured capabilities, mounts, CPU, memory, map pressure, and drops
- managed `whatap-network-agent` container in `whatap-node-agent` Pod when SCC permits
- standalone DaemonSet remains available when privilege or rollout isolation requires it

## Completion boundary

A feature is complete only when the same controlled flow is proven at every relevant boundary:

```text
kernel -> map -> poll -> Observation -> EdgeWindow -> sender -> server -> query/API -> UI
```
