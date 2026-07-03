#!/bin/bash
# Entrypoint for the quip-network-node image.
#
# Host environment (not node configuration):
#   PUID / PGID   uid/gid to run the node as (default 1000:1000; PUID=0 = root)
#
# Node state lives at /data (image WORKDIR, volume target in our compose and
# deployments). A --base-path outside /data is not supported: the ownership
# fix and the db_version repair below only cover /data.
set -euo pipefail

NODE_BIN=/usr/local/bin/quip-network-node

# --- RocksDB db_version self-heal -------------------------------------------
# A node killed mid-write (OOM, SIGKILL, host crash) can leave the tiny
# `db_version` marker truncated to 0 bytes. sc-client-db then aborts with
# "Database version cannot be read from existing db_version file"
# (UpgradeError::UnknownDatabaseVersion) and the node refuses to start, even
# though the RocksDB data itself is intact at the current schema version.
#
# A genuinely *missing* marker is fine — substrate treats it as a fresh db — so
# we only repair markers that EXIST but are unreadable/non-numeric, and only
# when a populated RocksDB lives alongside (its `CURRENT` manifest pointer).
# We never invent a marker where none exists: that would make substrate misread
# a fresh or partial db as v${DB_VERSION} and corrupt it.
#
# QUIP_DB_VERSION must track sc-client-db's CURRENT_VERSION
# (substrate/client/db/src/upgrade.rs); it is baked into the image (Dockerfile).
DB_VERSION="${QUIP_DB_VERSION:-4}"

repair_marker() {
    local marker=$1 dir contents
    dir=$(dirname "$marker")
    # Only touch a populated RocksDB; `CURRENT` is its live manifest pointer.
    [ -f "$dir/CURRENT" ] || return 0
    contents=$(cat "$marker" 2>/dev/null || true)
    # Valid markers are a bare non-negative integer; leave those untouched.
    # Empty or anything with a non-digit (whitespace, garbage) is corrupt.
    case "$contents" in
    '' | *[!0-9]*)
        echo "entrypoint: repairing corrupt db_version at $marker (was '$contents') -> $DB_VERSION"
        printf '%s' "$DB_VERSION" >"$marker"
        ;;
    esac
}

# The chain-id and db-kind path segments vary at runtime (chain spec id, db
# backend), hence the glob; the /data root is fixed by the image contract.
for marker in /data/chains/*/db/*/db_version; do
    [ -f "$marker" ] || continue # no glob match -> literal path, skip
    repair_marker "$marker"
done
# ---------------------------------------------------------------------------

# --- Privilege drop ----------------------------------------------------------
# Container starts as root so it can repair markers and fix /data ownership
# (fresh named volumes are root-owned on some Docker versions/platforms); the
# node runs as `quip`. PUID/PGID map the in-container user to a host uid/gid
# (default 1000:1000; PUID=0 keeps root).
PUID="${PUID:-1000}"
PGID="${PGID:-1000}"

if [ "$PUID" = "0" ]; then
    echo "entrypoint: PUID=0 — running as root"
    exec "$NODE_BIN" "$@"
fi

[ "$(id -g quip)" != "$PGID" ] && groupmod -g "$PGID" quip
[ "$(id -u quip)" != "$PUID" ] && usermod -u "$PUID" -g "$PGID" quip
chown -R quip:quip /data
echo "entrypoint: exec as uid=$PUID gid=$PGID"
exec gosu quip:quip "$NODE_BIN" "$@"
