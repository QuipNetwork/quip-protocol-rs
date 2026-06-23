#!/bin/sh
set -eu
# Fresh named volumes are root-owned on some Docker versions/platforms;
# ensure /data is writable by the unprivileged runtime user before exec.
chown -R quip:quip /data

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

# Resolve --base-path (alias -d) from the node args; default matches our images.
base_path=/data
prev=
for arg in "$@"; do
    case "$prev" in
    --base-path | -d) base_path=$arg ;;
    esac
    case "$arg" in
    --base-path=*) base_path=${arg#--base-path=} ;;
    -d=*) base_path=${arg#-d=} ;;
    esac
    prev=$arg
done

repair_marker() {
    marker=$1
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
        chown quip:quip "$marker"
        ;;
    esac
}

for marker in "$base_path"/chains/*/db/*/db_version; do
    [ -f "$marker" ] || continue # no glob match -> literal path, skip
    repair_marker "$marker"
done
# ---------------------------------------------------------------------------

exec gosu quip /usr/local/bin/quip-network-node "$@"
