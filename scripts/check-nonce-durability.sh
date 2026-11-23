#!/usr/bin/env bash
# Nonce durability on a throwaway PostgreSQL 17 container with its own cluster. Not part of CI.
#   1. Issuing waits for no WAL flush: 100 sequential issues add fewer than 50 WAL syncs
#      (about 100 when every issue commits synchronously). The counter is cluster wide, so this
#      cannot run next to other tests.
#   2. Crash check: the pool starts with synchronous_commit = off. Issue 5 nonces (the cap holds),
#      consume 1, issue 1 more, then kill -9 the database and start it again. The consumed nonce
#      must stay gone, the 4 issued before the consume must survive (the consume commit flushed
#      them), and the live count must not pass the cap. The last nonce may be lost; that is the
#      documented contract.
# Usage: scripts/check-nonce-durability.sh   (needs docker and cargo)
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
name="pact-nonce-check-$$"
tmp="$(mktemp -d)"
cleanup() { docker rm -f -v "$name" > /dev/null 2>&1 || true; rm -rf "$tmp"; }
trap cleanup EXIT

port=""
for _ in $(seq 20); do
  candidate=$((20000 + RANDOM % 40000))
  if docker run -d --name "$name" -e POSTGRES_PASSWORD=probe -p "127.0.0.1:$candidate:5432" \
    postgres:17-alpine > /dev/null 2>&1; then port="$candidate"; break; fi
done
[ -n "$port" ] || { echo "FAIL: no free port"; exit 1; }
export NONCE_PROBE_URL="postgres://postgres:probe@127.0.0.1:$port/postgres"
export NONCE_PROBE_FILE="$tmp/probe.txt"

ready() {
  for _ in $(seq 60); do
    docker exec "$name" psql -h 127.0.0.1 -U postgres -Atc 'select 1' > /dev/null 2>&1 && return
    sleep 1
  done
  echo "FAIL: database not ready"; exit 1
}
# Each phase runs once: the crash check issues its nonces in "before-crash".
probe() {
  local out
  if ! out="$(cd "$root" && NONCE_PROBE="$1" cargo test -q -p open-pact-gateway durability_probe -- \
    --ignored --nocapture 2>&1)"; then
    tail -20 <<< "$out"; echo "FAIL: phase $1"; exit 1
  fi
  grep -E 'wal_sync|READY|after the crash' <<< "$out" || true
}
ready
echo "== 1. issuing waits for no WAL flush"
probe wal-sync

# A long WAL writer delay keeps an unflushed commit unflushed until the kill.
docker exec "$name" psql -h 127.0.0.1 -U postgres -Atc "ALTER SYSTEM SET wal_writer_delay = '10s'" > /dev/null
docker exec "$name" psql -h 127.0.0.1 -U postgres -Atc 'select pg_reload_conf()' > /dev/null
echo "== 2. crash check"
probe before-crash
docker kill -s KILL "$name" > /dev/null
docker start "$name" > /dev/null
ready
probe after-restart
echo "ok"
