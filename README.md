# coraza-mlcheck

Coraza custom action that hands the current HTTP request to the **Argus
Sentinel v4** ML classifier over a Unix Domain Socket (gRPC) and writes the
verdict into transaction-scoped `TX:` variables that downstream SecLang rules
act on. This is the client half of the integration; the server half is
[datndptit/argus-sidecar](https://github.com/datndptit/argus-sidecar).

## Architecture

```
+----------------------+         +-------------------------+
|  Caddy + Coraza      |  UDS    |  Argus Sentinel sidecar |
|  (mlcheck action)    | <-----> |  Python + ONNX Runtime  |
|  /run/argus/         |  gRPC   |  v4 model bundle        |
|     argus.sock       |         |                         |
+----------------------+         +-------------------------+
```

Both containers share the same Linux socket volume. Measure RPC latency on
your host; UDS and inference time are part of the synchronous request budget.

The model is a **binary** clean/attack classifier: the wire response carries a
single `attack_prob` (mapped to `risk_score`) and at most the `attack`
detection label. See `proto/argusv1/argus.proto` for the exact v4 semantics of
each field.

## Build

Use the published Go module, with an explicit release:

```sh
xcaddy build v2.11.7 \
  --with github.com/corazawaf/coraza-caddy/v2@v2.6.1 \
  --with github.com/datndptit/coraza-mlcheck@v0.1.0
```

For Ingressi, add this module to `docker/caddy/go.mod`, its blank import to
`tools.go`, and its name to `build.sh`'s pinned module list. Keep all existing
Ingressi modules. No local source `replace`, extra Docker build context or
protoc installation is needed: generated Go stubs ship in this repository.
The release requires Coraza v3.8.1. Linux containers run on Ubuntu 24.04;
Caddy and the sidecar should use the same UID/GID (default 10000:10000) and
socket volume. Build Caddy before enabling rules containing `mlcheck`.

### Local development

```sh
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
# Install buf separately if using make proto; protoc also works.
make proto     # buf generate with local plugins (no protoc needed)
make test      # real-Coraza integration tests with a mock sidecar over a UDS
```

`make proto-protoc` is the protoc-based development path. Committed stubs are used by consumers.

## SecLang usage

Paste one rule per line into the Ingressi custom directives box (the builder
drops continuation backslashes, `Include` and `SecRequestBodyAccess`, so keep
every directive on a single line). Rules must run in **phase 2**: the request
body buffer is only populated once `ProcessRequestBody` runs. With the CRS
enabled (the default), body access is already on.

```apache
SecAction "id:1899999100,phase:2,pass,nolog,noauditlog,mlcheck"
SecRule TX:argus_is_clean "@streq 0" "id:1899999101,phase:2,pass,log,auditlog,ctl:auditEngine=On,severity:WARNING,msg:'Argus v4 detected',tag:'argus-sentinel/v4',logdata:'attack_prob=%{tx.argus_risk_score}'"
SecRule TX:argus_error "@rx .+" "id:1899999102,phase:2,pass,log,auditlog,severity:WARNING,msg:'Argus v4 unavailable',tag:'argus-sentinel/error',logdata:'reason=%{tx.argus_error}'"
```

`ctl:auditEngine=On` on the verdict rule is what makes a detection on a
request that keeps flowing (status 200) audit-visible: with the CRS loaded,
`@coraza.conf-recommended` sets `SecAuditLogRelevantStatus` to 4xx/5xx only,
which filters audited-but-200 transactions out. The error rule deliberately
omits it so a dead sidecar cannot turn into one audit event per request; its
signal is the Caddy log plus the mlcheck metrics summary.

Ready-to-use variants (detect / detect with a rule-level threshold / block)
live in [`examples/`](examples/). `id:1899999100-1899999199` is the recommended
operational range: above the RAW body rule `1899999000`, below the exclusion
records' `1900000000` base, and never reserved inside Ingressi itself.

## TX variables

| Variable | Values | Meaning |
|---|---|---|
| `tx.argus_is_clean` | `0` / `1` / `""` | `0` = attack verdict, `1` = clean verdict, empty = no verdict (fail-open). Rules that block on `@streq 0` stay inert on empty. |
| `tx.argus_risk_score` | float | `attack_prob`, full precision (shortest round-trip, no exponent), only with a verdict. |
| `tx.argus_detections` | `attack` / `""` | Set when the effective verdict is "attack" (v4 has one label). |
| `tx.argus_detection_attack` | float | `attack_prob` when flagged (per-label variable kept from the pre-v4 contract). |
| `tx.argus_status` | `ok` / `error` | Outcome of the evaluation that ran. |
| `tx.argus_error` | reason / `""` | Machine-readable failure reason (table below). |
| `tx.argus_skip` | `duplicate` / `""` | This invocation was suppressed by the one-RPC-per-transaction guard; the earlier verdict is untouched. |
| `tx.argus_threshold` | input | Optional float in `[0,1]`: the action then decides with `attack_prob > threshold` instead of the sidecar verdict, and keeps `argus_is_clean`/`argus_detections` consistent with it. |

Failure reasons (written to `tx.argus_error`): `client_init`, `rpc_error`,
`rpc_timeout`, `invalid_response`, `overload`, `circuit_open`,
`deadline_exceeded`, `wrong_phase`, `body_reader_unavailable`,
`body_read_error`, `invalid_threshold`, `internal`.

`@gt 0.998175` cannot be used on `argus_risk_score` — Coraza's operators parse
integers — which is why the threshold comparison happens inside the action.

### Behavior notes

- **Fail-open.** Every failure leaves `argus_is_clean` empty: the documented `@streq 0` rule does not match it, CRS decisions stand, and failures are never counted as
  model-confirmed clean. Use the error rule (or metrics) to alert.
- **One RPC per transaction.** A second `mlcheck` invocation (e.g. a global
  rule merged with a host rule) sets `argus_skip=duplicate` and changes
  nothing else.
- **Raw body.** The action reads the raw body prefix (≤4 KiB) from Coraza's
  body buffer via `RequestBodyReader()` — independent of body processors.
  JSON/XML bodies are forwarded even though `REQUEST_BODY` is empty for them.
- **Headers.** Only `user-agent`, `referer` and `cookie` are sent (lower-cased
  names, duplicate values joined `"; "` in header order). Authorization and
  everything else never leave the process.
- **URI.** `REQUEST_URI_RAW` is sent; the v4 preprocessing strips
  `scheme://host` and normalizes.
- **Concurrency guards.** In-flight RPCs are capped (`ARGUS_MAX_INFLIGHT`),
  excess requests wait a bounded time (`ARGUS_QUEUE_WAIT_MS`) then fail open
  as `overload`. Consecutive RPC failures open a circuit breaker
  (`ARGUS_CIRCUIT_FAILS`) for a cooldown (`ARGUS_CIRCUIT_COOLDOWN_MS`) with a
  single half-open probe; while open, calls fail open as `circuit_open`
  without touching the socket.
- **Deadline.** One budget (`ARGUS_TIMEOUT_MS`, default 50 ms) covers queueing
  and the RPC; a budget already exhausted before dispatch fails as
  `deadline_exceeded`.

## Configuration

| Knob | Default | Source |
|---|---|---|
| Socket path | `/run/argus/argus.sock` | `mlcheck:/path` argument → `$ARGUS_SOCKET` → default |
| RPC budget | `50ms` | `$ARGUS_TIMEOUT_MS` |
| Max in-flight RPCs | `64` | `$ARGUS_MAX_INFLIGHT` |
| Queue wait | `5ms` | `$ARGUS_QUEUE_WAIT_MS` |
| Circuit breaker | `10` consecutive failures / `5000ms` | `$ARGUS_CIRCUIT_FAILS`, `$ARGUS_CIRCUIT_COOLDOWN_MS` |
| Metrics summary interval | `60s` (`0` disables) | `$ARGUS_METRICS_INTERVAL_S` |
| Body cap sent to the sidecar | `4096 B` | constant `maxBodyBytes` (not a Coraza body limit) |

## Observability

Per-request failures are logged at debug level (they are the audit rule's job
to surface); aggregated counters are logged as one Info line every
`ARGUS_METRICS_INTERVAL_S` on the next request:

```
mlcheck metrics summary calls=… ok=… skipped_duplicate=… rpc_attempts=… failures="overload=… rpc_timeout=…" latency_buckets="<=1ms:…,…" latency_quantiles="p50<=2 p95<=5 p99<=10 ms (n=…)"
```

The line goes through Coraza's debug logger, which coraza-caddy wires to the
Caddy log (visible in `docker logs ingressi-caddy`). `SnapshotStats()` exposes
the same counters for tooling. Timeouts and other failures never increment
`ok`.

## Tests

`go test ./...` runs an end-to-end suite against real Coraza and a mock
sidecar over an actual Unix socket: raw-body forwarding for
URLENCODED/JSON/XML/RAW, detect-rule denial, fail-open when the sidecar is
down, `TX:argus_threshold` overrides, invalid-threshold fail-open, the
duplicate guard, header joining + `REQUEST_URI_RAW`, the wrong-phase guard,
limiter/breaker units, and the metrics summary format.

## Provenance

Derived from the pre-v4 `coraza-mlcheck` bundle (MobiFone ANM), adapted to the
Argus Sentinel v4 binary contract. Copyright 2026 MobiFone ANM; Apache-2.0.
