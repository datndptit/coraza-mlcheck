# Current Ingressi + Argus Sentinel v4

Reviewed Ingressi revision: `b0802aa8d442048092d8d901bcb8d87d1d742aaf`
(12 October 2026). Production target: Ubuntu 24.04 amd64, Docker Engine and
Compose v2. No Ingressi UI, API or database changes are required.

## Preserve the upstream build

Ingressi has a version-pinning Go module in `docker/caddy/`. `Dockerfile`
runs `update-compatibility-pins.sh`, installs the pinned xcaddy tool, and
calls `build.sh`. The script derives Caddy and plugin versions from `go.mod`.
The manifest's blank imports in `tools.go` prevent `go mod tidy`/Dependabot
from pruning the modules. `update-compatibility-pins.sh` manages cel-go
compatibility. Preserve all these steps and existing modules, including
Bunny DNS in the reviewed revision.

Add the released action in three places: `go.mod` (version `v0.1.0`),
`tools.go` (blank import), and `build.sh` (unversioned path in MODULES).
Refresh `go.sum`. The Caddy image must also initialize `/run/argus` owned
by its configured PUID/PGID for the shared socket volume.

The [reviewed patch](../examples/ingressi/caddy.patch) contains those changes
against the revision above. From a clean Ingressi checkout, with this repo
cloned beside it as `../coraza-mlcheck`:

```sh
git apply --check ../coraza-mlcheck/examples/ingressi/caddy.patch
git apply ../coraza-mlcheck/examples/ingressi/caddy.patch
cp ../coraza-mlcheck/examples/ingressi/docker-compose.argus.yml .
```

If your checkout already contains the integration, skip applying the patch.
If the patch does not apply to a newer revision, reconcile these small edits
with upstream instead of replacing the Caddy directory. On Windows, save
Docker shell scripts with LF line endings (the Linux build executes them).
No `/src/coraza-mlcheck` replacement, local source COPY, or protobuf compiler
is needed. The Go release contains generated stubs.

## Private model and socket

Prepare the trusted v4 bundle with
[argus-sidecar/scripts/prepare-model.py](https://github.com/datndptit/argus-sidecar/blob/main/scripts/prepare-model.py).
It copies `model.onnx`, `tokenizer.json`, `config.json`, `preprocess.py`,
`inference_cpu.py` and writes `MANIFEST.sha256`. The public image has no model.
Set permissions so the runtime UID/GID can read all files and traverse the
model directory; defaults are 10000:10000. The sidecar stack mounts this
directory read-only; the Ingressi stack never mounts the model.

Add to the existing Ingressi `.env` (keep its existing required credentials):

```dotenv
COMPOSE_FILE=docker-compose.yml:docker-compose.argus.yml
ARGUS_SOCKET_VOLUME=ingressi-argus-run
ARGUS_TIMEOUT_MS=50
```

`COMPOSE_FILE` uses `:` on Ubuntu. Retain any additional overlays your
installation already needs. The overlay deliberately contains no sidecar
service: deploy the sidecar from its own repository stack
([argus-sidecar](https://github.com/datndptit/argus-sidecar)) and start it
first so a fresh volume is created with the right ownership. The overlay
mounts the socket volume as an **external** volume named by
`ARGUS_SOCKET_VOLUME` (default `ingressi-argus-run`); the Ingressi project
never creates or removes it. There are no sidecar host ports. Both
containers must have matching UID/GID. One socket volume per Caddy/sidecar
pair.

The overlay sets `COMPOSE_EXTRA_FILE=/compose/docker-compose.argus.yml`
on **l4-port-manager**. This is necessary: that service explicitly passes
`-f` when recreating Caddy and would otherwise ignore `COMPOSE_FILE`, revert
to the base Caddy image and lose the socket mount. Recreate the port manager
with the overlay too. If already using COMPOSE_EXTRA_FILE for another
purpose, combine the required overrides into that extra file.

## Build and start

From the patched Ingressi checkout:

```sh
docker compose config --quiet
docker compose build caddy
docker compose up -d --no-deps --no-build --pull never caddy l4-port-manager

docker compose exec caddy caddy build-info | grep github.com/datndptit/coraza-mlcheck
docker compose exec caddy caddy list-modules | grep dns.providers.bunny
```

Start the sidecar stack (its own repository README) before recreating
Caddy: the socket volume is external, so Compose fails on a missing volume
instead of silently starting an ML-less Caddy. This updates services of an
existing, configured Ingressi installation. For a fresh installation,
follow the upstream setup for the rest of the stack too. All later Compose
operations must retain the ML overlay. Do not pull the base upstream Caddy
image over the custom build.

The prebuilt sidecar uses UID/GID 10000. If PUID/PGID differ, rebuild the
sidecar in its own repository with matching `--build-arg PUID=... PGID=...`
(see its README) and adjust model and socket-volume permissions
accordingly; set `PUID`/`PGID` for the Caddy service as usual. The host is
Ubuntu 24.04; the Caddy container's base remains upstream's Ubuntu 26.04,
and the sidecar uses Debian bookworm/Python 3.12.

## Rules and current WAF behavior

Enable WAF and **Load OWASP CRS**, then paste [detect.conf](../examples/detect.conf)
into existing WAF custom directives. After reviewing real traffic, switch
to [block.conf](../examples/block.conf) with WAF mode `On`.

- The current `src/lib/caddy-waf.ts` filters directives and appends custom
  rules after CRS. All three supplied rule templates survive filtering;
  `ctl:auditEngine=On` makes a detect-only HTTP 200 auditable.
- CRS enables request-body access and JSON/XML/form/multipart processors;
  Ingressi selects RAW for other content types. The plugin reads the raw
  buffered body rather than depending on REQUEST_BODY being populated by
  a particular parser. Keep CRS loaded for this supported configuration.
- ML contributes an additional verdict; it cannot reopen a CRS-blocked
  request. If CRS blocks first, ML may never run. Fail-open applies only to
  ML failures: CRS still decides independently.
- `@streq 0` is required for blocking, so an absent verdict does not match.
  Use the TX threshold template for floating-point thresholds; do not use
  the integer `@gt` operator to compare probabilities.
- Global directives precede host directives in merge mode. A host threshold
  after a global mlcheck is too late. Put the complete ML set on the host or
  use host override. Do not duplicate template IDs in global and host rules.
- With `allowWebsocket=true`, **only upgrade handshakes** bypass the WAF.
  Ordinary HTTP on the same host still passes through WAF/ML. L4 traffic
  has no HTTP WAF; WebSocket frames are not inspected.

Build the binary and start the sidecar before saving ML rules: an image
without the registered action rejects the config. For rollback, remove
all ML rules and apply config before replacing the custom Caddy image.
Keep versioned model directories as well as image digests for rollback.

## Validation boundaries

The compatibility workflow builds this exact upstream revision through its
own Dockerfile, tests the released action with Ingressi's dependency graph,
and validates a fixture produced by its WAF builder (with embedded CRS).
The fixture is a test configuration, not a production Caddy configuration.
Local tests additionally exercise the real private v4 model over UDS and
HTTP, including body preservation, detect/block, failure and recovery.

The reviewed manifest selects Caddy v2.11.7, coraza-caddy v2.6.1, Coraza
v3.8.1, CRS v4.25.0, gRPC v1.83.2 and protobuf v1.36.12. These are observed
pins, not instructions to hardcode them elsewhere. Future upgrades of
Coraza's experimental action API must repeat these checks. CI and Docker
checks are not production capacity testing or deployment acceptance.
