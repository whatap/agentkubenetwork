# Direct TagCount: HTTP, DNS and collection coverage

`-export=tagcount` sends supported HTTP/DNS observations and L7 coverage records
through the same bounded asynchronous exporter as L4 windows. `-export=none`
remains the default. The Java local bridge remains L4-only. This does not add a
second Kubernetes metadata collector or deploy an agent automatically.

## Record categories

| Category | Unit and important fields |
|---|---|
| `kube_network_http_v1alpha1` | One observed HTTP transaction: `protocol`, `http_method`, `http_status`, `latency_us`, `transaction_count=1`, original client/server tuple, source and boundary |
| `kube_network_dns_v1alpha1` | One DNS correlation outcome: `query_name`, `query_type`, `outcome`, `response_count`, `transaction_count=1`, observed client/server tuple; `rcode` for observed responses, `latency_us` only for measured query/response pairs |
| `kube_network_coverage_v1alpha1` | Collector/correlator drops: `source`, `protocol`, `reason`, `reported_count`, `coverage_record_count`; these are **not service request failures** |

The records carry `observer_node`, `record_id`, `observed_at_ms` and the observed PID when
available. HTTP/DNS retain `observer_container_id` and validated translated tuple
evidence when available; process start ticks participate only in the fingerprint.
Live Pod identity is enabled by default: HTTP exports `src_pod_uid`,
`dst_pod_uid`, `observer_pod_uid`; DNS exports `client_pod_uid`,
`server_pod_uid`, `observer_pod_uid`, with corresponding namespace/name tags.
These identities are snapshotted at request/query capture and survive correlation;
they are not looked up again at response/expiry time. See [Pod identity](pod-identity.md).
Missing identity/translation
is omitted rather than reconstructed from a name or a current endpoint list.

The pack fingerprint includes the observation's nanosecond timestamp and
non-private correlation fields. The exporter appends a serialized enqueue
ordinal, so indistinguishable observations in one batch are not collapsed.
Compare records as **multisets**, not sets keyed only by rounded time or tuple.

## Metric meaning and privacy

- HTTP/1 boundary: `request_to_response_status` — the parser can complete on a
  final status line. It does not wait for the whole header block or response body.
- HTTP/2 boundary: `request_to_response_headers`. This is not necessarily gRPC
  stream completion. Informational responses and stream zero are not completed
  HTTP transactions.
- HTTPS requires explicitly selected, compatible OpenSSL libraries. This is not
  generic Go/Java TLS instrumentation. Supply the matching `libcrypto` as well as
  `libssl` when BIO symbols live there. Incomplete read/write/context-to-fd
  attachment fails closed; do not disable that guard.
- `no_response` is an observation outcome, not proof of a service timeout
  or NetworkPolicy rejection. `incomplete` means capture end/state-capacity
  interruption. Neither has a measured latency or a fabricated zero latency.
- DNS `response_count=1` and `rcode` remain available for unmatched responses.
  `latency_us` is omitted unless a query matched and both kernel timestamps are
  nonzero and nondecreasing. Equal timestamps and sub-microsecond durations are
  legitimate measured zero samples. JSONL `latencyMeasured=true` identifies a
  measured sample; when its `latencyMicros` is omitted, the measured value is zero.
  Absent/false `latencyMeasured` means unmeasured, not zero. The pack builder rejects
  nonzero latency without measurement and measurement without a response.
- Kernel/correlation loss is sent separately from HTTP status and DNS response
  outcome. An observed 5xx is different from a parser or ring-buffer drop.
- Percentiles can be calculated from the stored **observed samples** with the
  same source, protocol, observer and measurement boundary. This does not prove
  population coverage or unique request rate across both sides of a connection.
- Do not subtract SRTT from HTTP duration to obtain application execution time.
- URL/path, query string, raw headers/payload, process command and command line
  are not exported by the HTTP/DNS pack builders. DNS query names are bounded
  protocol metadata: at most 253 bytes of visible ASCII (bytes 33–126).
  Unsupported captured question names become `parse_failed` with unknown question
  fields, never raw malformed labels or fatal exporter errors. Manual invalid packs
  still fail validation. Record IDs do not incorporate the omitted HTTP/process data.

## Existing Kubernetes data

When `observer_pod_uid` is present, join that exact UID to `kube_pod.podUid`.
For older/unattributed records, join `observer_container_id` to full `container.containerId`, then follow
`container.podUid` to `kube_pod.podUid`. Validate project, original observation
clock, snapshot age, namespace and Pod name; reject contradictory/ambiguous IDs.
The observer may be the server, not the source Pod. No short-ID/hash/name fallback.

Reuse `kube_service` for Service UID/address metadata.
`kube_service_pod_mapping` has parallel `serviceUid[]` and `podUid[][]` fields;
it is configured membership, may include NotReady or stale members, and does
**not** identify the backend that handled a request. Existing `kube_hpa` snapshots
and `kube_network_policy` events retain their separate time/intent semantics.
Missing historical state is not normal/zero, and current state is not backfilled.

## Queue, shutdown and verification

All four categories share one queue, connection, failure signal and drain budget.
JSONL evidence is enqueued before export. After the first export rejection,
already-produced HTTP/DNS/drop/window batches remain eligible for JSONL output
without further submission to the failed exporter. JSONL I/O/queue/drain failures
still remain errors and its existing bounds are unchanged.

`queued`, `written`, `failed`, `pending` and `dropped` now count all exported record
kinds. `written` is only successful TCP writing, **not a storage acknowledgement**.
A live gate must re-read the same project/OID/time interval and compare every
field, optional-field presence and multiplicity against the actual pack builders.

The tested backend's query `time` is second-granular. Use `observed_at_ms` for the
original L7/DNS/coverage time; do not replace it with the query index time.
The L4 `window_start_ms` likewise remains its original window clock.

Unit/race tests do not replace a real-kernel/storage gate. A successful bounded
canary is not proof of every kernel, TLS runtime, long-term load or production
DaemonSet configuration. Keep canary UID-scoped cleanup and verify that its BPF
programs, maps and links are gone. Preserve complete JSONL through log rotation;
otherwise an exporter counter cannot prove how many source records were stored.
