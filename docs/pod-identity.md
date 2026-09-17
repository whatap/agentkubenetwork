# Default-on Pod UID enrichment

Live `-source=ebpf` enables Pod UID enrichment by default for L4, HTTP/1,
HTTP/2 and DNS. Use `-pod-identity=false` for an explicitly unenriched capture.
The default stdin batch path does not contact Kubernetes. Coverage records and
the optional Java bridge do not gain Pod enrichment from this feature.
It works with live raw/windows/both output and direct TagCount export.

## Configuration and lifecycle

- Without `-kubeconfig`, use only Kubernetes in-cluster configuration. There is
  no implicit `$HOME/.kube/config` lookup.
- `-kubeconfig=/path/to/config` explicitly selects a trusted kubeconfig for live
  capture and cannot be combined with `-pod-identity=false`. Kubeconfig exec authentication can execute programs;
  use only administrator-approved configuration.
- `-pod-sync-timeout=10s` must be positive. Initial LIST synchronization must
  succeed before opening the eBPF reader; configuration/RBAC/sync failures abort
  startup. The same duration bounds waiting for informer shutdown.
- One cluster-wide, Pod-only SharedIndexInformer performs LIST then WATCH using
  Kubernetes resource versions. client-go owns reconnect/relist behavior. There
  are no per-observation API requests and no periodic full inventory export.
- Process cancellation stops the watch; cancelled or unsynced caches do not
  attribute observations. A synchronized cache is current state, not a freshness
  guarantee while the API is unreachable; there is no historical cache or
  watch-disconnection TTL in this version.

## Attribution contract

L4/HTTP `sourcePod`, `destinationPod`, and `observerPod` contain `uid`,
`namespace`, and `name`. DNS uses `clientPod`, `serverPod`, and `observerPod`.
Unknown identities are omitted, never synthesized from IPs or names.

Canonical source/destination use NAT-resolved endpoint addresses when available,
otherwise the normalized raw endpoint address. PodIP and all PodIPs are indexed,
including normalized IPv6 and IPv4-mapped addresses. A unique normalized runtime
container ID from regular, init, or ephemeral container status identifies the
**observer**, which must never be assumed to be the canonical source.

Ambiguous matches, missing UIDs, unsynced/stopped caches, and observations older
than the matched Pod's known creation time remain unknown. Host-network IPs
cannot safely identify endpoints; a unique container ID may still identify a
host-network observer. The cache does not reconstruct deleted Pods or historical
IP ownership. Resource churn/API delay can leave attribution unknown or stale;
this is not a historical identity database.

L4 UID identity is attached before window aggregation. Different or unknown Pod
identities do not merge in the same flow/time bucket. HTTP and DNS snapshot Pod
identity with the request/query fragment, before correlation. A later response,
Pod replacement, expiry or capture shutdown must not replace that snapshot;
unknown request identity is not backfilled from a later response. An unmatched
DNS response retains only its own observed, direction-normalized identity.

Malformed DNS packets with a complete header use its query/response bit to
normalize endpoint and Pod direction together. Without a complete header,
client/server Pod and resolved attribution are omitted. The original endpoint
order remains only as a parse-error diagnostic tuple; observer identity is
independent and is retained. Such tuples are not verified client/server edges.

JSONL and direct TagCount preserve the same identities. L4/HTTP use
`src_pod_uid`, `dst_pod_uid`, `observer_pod_uid`; DNS uses `client_pod_uid`,
`server_pod_uid`, `observer_pod_uid`. Each has corresponding `_pod_namespace`
and `_pod_name` tags when known. These are persisted fields, not an offline join.
Old stored records are not rewritten. Backend readback of a newly deployed image
and Service/Workload aggregation remain separate acceptance gates.

## Least-privilege RBAC example (not applied)

The informer needs only core API Pod `list` and `watch` across namespaces. It does
not need Secrets, Nodes, Services, writes, or per-Pod `get`. Bind this example
role to the actual agent service account through the deployment's existing RBAC
management; do not apply it without deployment approval.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: whatap-network-pod-identity
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["list", "watch"]
```

No deployment manifests or live RBAC were changed. Local tests use only
`httptest` API servers and temporary fixture kubeconfigs; they verify initial
LIST, resourceVersion WATCH continuity, MODIFIED indexing, cancellation, bounded
sync timeout, default-on/explicit opt-out behavior, request-time identity
preservation and UID propagation into JSONL/TagCount. The agent service account
still needs a mounted token (or explicit trusted kubeconfig) and these existing
read permissions; the binary never grants itself RBAC.
