# Operational logging and telemetry stdout

Telemetry is not an operational log level. The two controls are independent:

| Flag | Environment variable | Default | Contract |
|---|---|---|---|
| `-stdout=auto\|jsonl\|none` | `WHATAP_STDOUT` | `auto` | `auto` selects `none` with `-export=tagcount`, otherwise `jsonl`. `none` requires TagCount so the only telemetry sink cannot be silently disabled. `jsonl` restores diagnostic output. |
| `-log-level=debug\|info\|warn\|error` | `WHATAP_LOG_LEVEL` | `info` | Strict lowercase values. Periodic TagCount summaries run at info/debug only. Debug never enables raw telemetry. |
| `-log-interval=DURATION` | `WHATAP_LOG_INTERVAL` | `1m` | Nonnegative Go duration. `0` disables periodic summaries, not the final summary or fatal errors. |

Precedence is **explicit CLI flag > environment variable > binary default**, independently for each option. An explicit flag wins even when it equals the default or the overridden environment value is invalid. An unset variable uses the default; a present but empty, malformed, negative, or overflowing value is rejected before stdin consumption, informer setup or BPF attach. Values are not trimmed or case-normalized. Environment diagnostics identify the variable without echoing its contents. These logging variables are not read from `whatap.conf`.

## Kubernetes environment configuration

For a standalone DaemonSet, add these entries to the existing network-agent container's `env` list (preserve its credentials, node identity, resources, mounts and other settings):

```yaml
env:
  - name: WHATAP_STDOUT
    value: "auto"
  - name: WHATAP_LOG_LEVEL
    value: "info"
  - name: WHATAP_LOG_INTERVAL
    value: "1m"
```

`valueFrom.configMapKeyRef` and `envFrom.configMapRef` also work. Environment variables are resolved at process startup, not reloaded dynamically. A ConfigMap data-only update does not restart existing Pods or refresh their environment; a separately authorized rollout is required.

The matching Operator exposes the same container entries under `spec.features.networkAgent.env` and `spec.features.networkAgent.envFrom`. Its existing `stdout`, `logLevel` and `logInterval` fields generate explicit CLI flags and therefore override the matching environment variables. Leave those fields unset (remove them from an existing CR when switching to env) if the environment should control logging. Do not replace the Operator-managed credential, identity or Go memory-limit variables. See the Operator's `NETWORK_AGENT.md` and `config/samples/network-agent-logging-env-patch.yaml`.

These controls require a collector image built from the updated source. Operator configuration additionally requires its matching Operator image and CRD; older CRDs may prune the new fields. Editing YAML alone does not add support to already-running images. No deployment is performed by this change.

## Output and delivery semantics

`-output-mode=raw|windows|both` still selects L4 record shape; it does not select a destination. Direct TagCount still requires live eBPF and windows/both. HTTP, DNS, coverage, aggregation and Pod identity semantics are unchanged. The default stdin/export=none batch command still emits JSONL.

For normal direct export, use `-export=tagcount -output-mode=windows` and leave stdout at auto. To diagnose records explicitly, add `-stdout=jsonl`; raw/both TCP diagnostics can expose command lines. Do not publish them as ordinary operational logs.

TagCount writes compact cumulative JSON summaries to stderr. Existing `network.tagcount.summary/v1alpha1` counters and `stage:tcp_write` are retained, with `final` and `run_failed` booleans. A final summary is emitted after exporter shutdown at every level, including runtime failures and when periodic summaries are disabled. Configuration rejected before exporter setup remains a fatal diagnostic rather than a telemetry summary. Fatal errors remain visible on stderr at all levels and exit nonzero. No record bodies, query strings, command lines, credentials, or arbitrary error text are included in summary records; no startup record dumps configuration.

`written` means completed **TCP write**, not server ACK or durable storage. `failed`, `pending`, `dropped` and skipped counters retain their original meanings. Suppressed stdout skips JSON serialization and its queue without suppressing export or typed routing. The periodic reporter is cancelled and joined before final diagnostics, so periodic and final writes cannot race. A broken diagnostics writer is returned as an error; an indefinitely blocked generic stderr writer cannot be forcibly interrupted.

No transport retry, fail-open, connection policy, deployment or restart policy is changed by these controls.
