#!/usr/bin/env bash
# Rootless Postgres + WAL-G entrypoint for Tinfoil enclaves.
# Restores from R2 on first boot if a backup exists, configures continuous
# WAL archiving (client-side encrypted), and takes an initial base backup.
set -Eeuo pipefail

PGDATA="${PGDATA:-/var/lib/postgresql/data}"

# --- WAL-G / R2 configuration (from injected secrets) ---
export AWS_ACCESS_KEY_ID="${R2_ACCESS_KEY_ID:?need R2_ACCESS_KEY_ID}"
export AWS_SECRET_ACCESS_KEY="${R2_SECRET_ACCESS_KEY:?need R2_SECRET_ACCESS_KEY}"
export AWS_ENDPOINT="https://${R2_ACCOUNT_ID:?need R2_ACCOUNT_ID}.r2.cloudflarestorage.com"
export AWS_S3_FORCE_PATH_STYLE="true"
export AWS_REGION="${AWS_REGION:-auto}"
export WALG_S3_PREFIX="s3://${R2_BUCKET:?need R2_BUCKET}/${WALG_PREFIX:?need WALG_PREFIX}"
KEY_URL="${KEY_URL:-http://unlock:9090/key}"
echo "[walg-entrypoint] waiting for data key from unlock-gate ($KEY_URL)..."
until WALG_LIBSODIUM_KEY="$(curl -fsS --max-time 5 "$KEY_URL" 2>/dev/null)" && [ -n "$WALG_LIBSODIUM_KEY" ]; do sleep 3; done
export WALG_LIBSODIUM_KEY
echo "[walg-entrypoint] data key received from unlock-gate"
export WALG_LIBSODIUM_KEY_TRANSFORM="${WALG_LIBSODIUM_KEY_TRANSFORM:-none}"
export WALG_COMPRESSION_METHOD="${WALG_COMPRESSION_METHOD:-lz4}"
SOCKDIR="$(dirname "$PGDATA")/sock"   # socket OUTSIDE PGDATA so wal-g's tar doesn't choke on it
mkdir -p "$SOCKDIR" 2>/dev/null || true
export PGHOST="$SOCKDIR"   # writable socket dir for local tools, inside the data volume
export PGUSER="${POSTGRES_USER:-postgres}"   # wal-g connects as the superuser to run backups
export PGDATABASE="postgres"
export PGPORT="5432"

log() { echo "[walg-entrypoint] $*"; }

# --- Restore-on-boot: empty data dir + a backup exists in R2 -> fetch it ---
if [ ! -s "$PGDATA/PG_VERSION" ]; then
  mkdir -p "$PGDATA"; chmod 0700 "$PGDATA" 2>/dev/null || true
  if wal-g backup-list 2>/dev/null | grep -qE '^base_'; then
    log "existing backup found in R2 -> restoring LATEST"
    wal-g backup-fetch "$PGDATA" LATEST
    touch "$PGDATA/recovery.signal"
    printf "restore_command = 'wal-g wal-fetch \"%%f\" \"%%p\"'\n" >> "$PGDATA/postgresql.auto.conf"
    log "restore complete; postgres will replay WAL"
  else
    log "no backup in R2 -> fresh initdb"
  fi
fi

# --- After startup: take an initial base backup if none exists yet ---
(
  for _ in $(seq 1 150); do pg_isready -q 2>/dev/null && break; sleep 2; done
  for attempt in $(seq 1 12); do
    if wal-g backup-list 2>/dev/null | grep -qE '^base_'; then break; fi
    log "base backup attempt ${attempt} -> R2"
    if wal-g backup-push "$PGDATA"; then log "base backup done"; break; fi
    log "base backup attempt ${attempt} failed; retrying in 15s"
    sleep 15
  done
) &

# --- Hand off to the stock postgres entrypoint with continuous archiving on ---
exec docker-entrypoint.sh postgres \
  -c archive_mode=on \
  -c archive_command='wal-g wal-push "%p"' \
  -c archive_timeout=60 \
  -c unix_socket_directories="$SOCKDIR" \
  "${@:2}"
