#!/bin/sh
set -e
# Fresh named volumes are root-owned on some Docker versions/platforms;
# ensure /data is writable by the unprivileged runtime user before exec.
chown -R quip:quip /data
exec gosu quip /usr/local/bin/quip-network-node "$@"
