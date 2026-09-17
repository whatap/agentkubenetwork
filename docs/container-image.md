# Container image

Repository: `public.ecr.aws/whatap/network_agent_dev` (development image).

## Build and publish

Run the canonical Go checks, then `make image-binaries`. This creates static
`dist/linux/amd64/agentkubenetwork` and `dist/linux/arm64/agentkubenetwork` from the
current source tree. `DIST_DIR` can relocate the build output, but the Docker
context must keep the `dist/linux/<arch>/agentkubenetwork` layout.

The Dockerfile uses a digest-pinned official distroless static Debian base and
copies only the target binary. The allowlist `.dockerignore` excludes source,
Git history, test captures, credentials, kubeconfigs and local settings. No Go
compiler or module cache is needed on the image assembly host.

For an authorized release:

```bash
make test check build
make image-binaries
python3 scripts/test_image_contract.py

docker buildx build --platform linux/amd64,linux/arm64 \
  --build-arg SOURCE_REVISION="$(git rev-parse HEAD)" \
  --build-arg SOURCE_SHA256="$SOURCE_SHA256" \
  -t "public.ecr.aws/whatap/network_agent_dev:$IMAGE_TAG" --push .
```

`SOURCE_REVISION` records the base commit; `SOURCE_SHA256` must be calculated from
the exact source manifest, because a dirty tree is not identified by its commit.
Use an immutable tag for validation and a registry digest for deployment. Publish
`latest` only as an explicit development-channel promotion after image smoke and
registry readback. Never run a registry login with shell tracing; pipe the AWS
password directly to Docker and use a temporary, task-owned Docker config.

## Runtime defaults and requirements

The image entrypoint is `/usr/local/bin/agentkubenetwork`, with default arguments:

```text
-source=ebpf -output-mode=windows -export=tagcount
```

Live Pod identity is **enabled by the binary default**. Runtime `args` replace the
image CMD; when overriding arguments, retain the desired source/output/export
flags. `-pod-identity=false` is an explicit opt-out, not a fallback for missing
permissions. The bare binary's default source remains stdin and export remains
none; the image CMD is what selects live direct export.

Binary defaults `-stdout=auto -log-level=info -log-interval=1m` suppress duplicate
telemetry stdout for this direct-export CMD and emit compact stderr summaries.
Use `-stdout=jsonl` only for explicit record diagnostics; debug does not enable
raw records. `-log-interval=0` disables periodic summaries, not final summaries
or fatal errors. See [logging controls](logging.md).

The same settings can be supplied through `WHATAP_STDOUT`, `WHATAP_LOG_LEVEL`
and `WHATAP_LOG_INTERVAL` in the container's `env`, `valueFrom`, or `envFrom`.
Explicit logging arguments override the matching environment variables; unset
variables use binary defaults. Empty or invalid effective values fail startup.
The image CMD does not force logging arguments, so environment-only configuration
works without replacing its source/output/export arguments. ConfigMap updates
require a separately authorized Pod rollout; logging is not hot-reloaded.

Required runtime inputs, supplied by the deployment rather than the image:

- `NODE_NAME` from `spec.nodeName`, plus an approved project's `WHATAP_ACCESSKEY`
  and `WHATAP_SERVER_HOST` (or a mounted config selected by `-whatap-config`).
- A mounted service-account token and existing cluster-wide core Pod `list/watch`
  permission; alternatively an explicit trusted `-kubeconfig`. Missing config or
  failed initial informer sync aborts startup instead of silently omitting UIDs.
- A supported Linux kernel with BTF, required tracepoints and BPF/fentry privileges.
  The image runs as root for this collector; the deployment must supply its
  reviewed capabilities/SCC and host tracing mounts.
- Host PID visibility/procfs access for observer container identity. Host-network
  conntrack visibility is needed when resolving node NAT tuples.
- HTTPS plaintext capture is still opt-in with compatible target `libssl` and
  `libcrypto` paths; packaging does not add generic Go/Java TLS instrumentation.

The image has no shell or package manager. A network-free packaging smoke is
`docker run --rm --network=none IMAGE -h`; stdin fixtures can be passed with
`-source=stdin`. This is not a real-kernel or backend persistence test.

L4/HTTP export `src_pod_uid`, `dst_pod_uid`, `observer_pod_uid`; DNS exports
`client_pod_uid`, `server_pod_uid`, `observer_pod_uid`, each with namespace/name
when known. Unknown or ambiguous identity remains absent. Image publication does
not roll out an agent, change RBAC, backfill old TagCount rows or verify new live
UID storage. Those are separate deployment and readback gates.
