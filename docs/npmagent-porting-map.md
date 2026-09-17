# npmAgent porting map

Reference source:

- Repository: `whatap/npmagent`
- Reviewed baseline: `7952a03438c74766b0a3f170a1075eedf724deda`

The retired repository is evidence and a hook catalog, not a template to copy wholesale.

## Reuse as design evidence

| Legacy area | What to preserve | Porting rule |
|---|---|---|
| `bpf/c/common.h` | tuple and session field intent | define a new versioned ABI; do not inherit every map |
| `bpf/c/tcp.h` | candidate TCP hooks and kernel fields | port one hook at a time with a controlled Linux test |
| `bpf/c/udp.h` | candidate UDP send/receive hooks | begin only after the TCP vertical slice is stable |
| `bpf/bpf.go` | BTF loading and attach inventory | separate loader, poller, aggregator, and sender packages |
| `k8s/K8S.go` | need for node/Pod enrichment | use informer cache with Pod UID and valid-time identity |

## Explicitly do not copy

- the two-stage average-of-averages merge in `bpf/bpf_data.go`
- cumulative `lost_out`/`retrans_out` snapshots without a proven delta contract
- `rto` labeled as an actual timeout event
- the 5-to-60-second merge that discards internal window timestamps
- packet capture, AWS discovery, traceroute, and backend sender dependencies in the first kernel slice
- the retired `npm_process_tag_data` schema as the new canonical contract

## Selected direct transport port

The standalone TagCount path ports the required license format, AES-128 key-reset and TCP framing behavior from `gointernal/lang/license`, `gointernal/util/crypto`, and `gointernal/net/secure` into `internal/whatap`. The owner approved this limited internal reuse; no whole legacy package, global sender singleton, credential logging, remote command execution, or endless reconnect loop is imported. The existing `golib` provides `TagCountPack` and its codec; no local `npmagent` checkout is needed to build.

The new `kube_network_edge_v1alpha1` field contract and original window timestamps remain unchanged. See [direct transport configuration and limitations](direct-tagcount.md). This selected user-space transport port does not change the kernel-port acceptance criteria or assign a repository distribution license.

## First probe acceptance

The first kernel port is accepted only when a disposable Linux fixture proves:

1. object load and attach
2. exact test tuple
3. bytes/packets change under controlled traffic
4. RTT meaning and unit
5. no repeated delta when traffic stops
6. cleanup leaves no links or maps
7. the resulting `Observation` produces the expected 5-second window

## Licensing

The legacy eBPF object declares GPL compatibility for kernel helper access, but the repository has no top-level software license. Before copying source text into this public repository, WhaTap Labs must choose and add an explicit repository license and confirm internal source reuse terms. Until then, port behavior and tests, not bulk source files.
