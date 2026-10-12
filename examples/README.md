# examples/

Operational and test fixtures for the `mlcheck` action. Nothing here is
loaded automatically; everything is copy/paste or explicit-run material.

| File | What it is |
|---|---|
| `detect.conf` | SecLang rules: ML records only, CRS keeps blocking. The default rollout state. |
| `detect-tx-threshold.conf` | Same, but with a rule-level `TX:argus_threshold` (no sidecar restart needed to change it). |
| `block.conf` | Same as detect, but ML detections deny with 403 (WAF must be in `On` mode). |
| `caddy-e2e.json` | Minimal Caddy JSON config (handler `waf` + `mlcheck` rules + `static_response` upstream + audit log) used to smoke-test the built image against a live sidecar. |
| `run-caddy-e2e.sh` | End-to-end check: builds nothing, runs the caddy and sidecar images, asserts clean=200 / SQLi=403 / JSON-body XSS=403 / fail-open when the sidecar is stopped. |

Paste rules into the WAF custom directives box **one rule per line** — the
Ingressi builder drops continuation backslashes, `Include` and
`SecRequestBodyAccess`. See `../README.md` for the TX-variable contract and
[sidecar deployment guide](https://github.com/datndptit/argus-sidecar) for deployment.
Set `ARGUS_MODEL_DIR_HOST` to the prepared private model bundle before running the E2E script.
