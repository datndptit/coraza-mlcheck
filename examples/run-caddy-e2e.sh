#!/usr/bin/env bash
# End-to-end smoke test for the built images: Caddy (with the mlcheck plugin)
# + argus-sidecar over the shared UDS named volume.
#
#   ./run-caddy-e2e.sh [caddy-image] [sidecar-image]
#
# Checks:
#   1. clean request            -> 200
#   2. SQLi in the query string -> 403 (ML verdict, deny rule)
#   3. XSS in a JSON body       -> 403 (raw-body path: REQUEST_BODY is empty
#                                  for JSON, the action reads the body buffer)
#   4. sidecar stopped          -> requests fail OPEN (200) and the audit log
#                                  records "Argus v4 unavailable"
# Then prints the audit log tail. Exits non-zero on the first failed check.
set -euo pipefail

caddy_image="${1:-ingressi-caddy:test}"
sidecar_image="${2:-ghcr.io/datndptit/argus-sidecar:v0.1.0}"
model_dir="${ARGUS_MODEL_DIR_HOST:?Set ARGUS_MODEL_DIR_HOST to the prepared v4 bundle}"
url="http://127.0.0.1:18080"
sock_volume="argus-e2e-run"
log_volume="argus-e2e-logs"
examples_dir="$(cd "$(dirname "$0")" && pwd)"

# Git Bash / MSYS: docker needs a native path for bind mounts; MSYS path
# conversion is disabled in some setups, so convert explicitly when possible.
host_path() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}
config_mount="$(host_path "$examples_dir/caddy-e2e.json"):/etc/caddy/config.json:ro"

# MSYS curl fails writing response bodies to /dev/null (exit 23); the Windows
# null device is NUL. On Linux CI /dev/null is correct.
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) null_dev="NUL" ;;
  *) null_dev="/dev/null" ;;
esac

cleanup() {
  docker rm -f argus-e2e-caddy argus-e2e-sidecar >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker volume rm -f "$sock_volume" "$log_volume" >/dev/null 2>&1 || true
docker volume create "$sock_volume" >/dev/null
docker volume create "$log_volume" >/dev/null

echo "== starting sidecar =="
docker run -d --name argus-e2e-sidecar -v "$sock_volume":/run/argus -v "$(host_path "$model_dir"):/model:ro" "$sidecar_image" >/dev/null
for _ in $(seq 1 24); do
  [ "$(docker inspect --format '{{.State.Health.Status}}' argus-e2e-sidecar 2>/dev/null)" = "healthy" ] && break
  sleep 5
done
echo "sidecar health: $(docker inspect --format '{{.State.Health.Status}}' argus-e2e-sidecar)"

echo "== starting caddy =="
docker run -d --name argus-e2e-caddy -p 127.0.0.1:18080:8080 \
  -v "$sock_volume":/run/argus \
  -v "$log_volume":/logs \
  -v "$config_mount" \
  --entrypoint caddy "$caddy_image" run --config /etc/caddy/config.json >/dev/null
for _ in $(seq 1 24); do
  code="$(curl -s -o "$null_dev" -w '%{http_code}' -H 'User-Agent: Mozilla/5.0' "$url/ping" || true)"
  [ "$code" = "200" ] && break
  sleep 2
done
if [ "${code:-}" != "200" ]; then
  echo "FAIL: caddy did not come up"; docker logs argus-e2e-caddy 2>&1 | tail -20; exit 1
fi

check() { # name expected-url... => uses extra args as curl args
  local name="$1" expected="$2"; shift 2
  local code rc
  code="$(curl -s -o "$null_dev" -w '%{http_code}' -H 'User-Agent: Mozilla/5.0' "$@")" && rc=0 || rc=$?
  code="${code//$'\r'/}"
  if [ "$rc" = "0" ] && [ "$code" = "$expected" ]; then
    echo "PASS: $name -> $code"
  else
    echo "FAIL: $name -> code='${code}' curl_rc=${rc} (expected ${expected})"
    FAILED=1
  fi
}

FAILED=0

echo "== detection =="
check "clean request" 200 "$url/products?id=42&sort=price"
check "sqli in query" 403 "$url/products?id=42%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--"
check "xss in json body" 403 -X POST -H 'Content-Type: application/json' \
  --data '{"text":"<script>alert(document.cookie)</script>"}' "$url/comment"

echo "== fail-open (sidecar stopped) =="
docker stop argus-e2e-sidecar >/dev/null
check "sqli while sidecar down" 200 "$url/products?id=42%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--"

echo "== audit log tail =="
docker run --rm -v "$log_volume":/logs alpine sh -c 'tail -c 4000 /logs/waf-audit.log' || true

if [ "$FAILED" != "0" ]; then
  echo "E2E FAILED"
  exit 1
fi
echo "E2E OK"
