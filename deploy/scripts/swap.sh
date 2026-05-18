#!/usr/bin/env bash
# Stop every ares-* example service and start the one named.
# Usage:  sudo bash swap.sh {auction|rideshare|cohort-formation|cohort-weekly}
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 {auction|rideshare|cohort-formation|cohort-weekly}" >&2
    exit 2
fi

TARGET="$1"
case "$TARGET" in
    auction|rideshare|cohort-formation|cohort-weekly) ;;
    *) echo "unknown target: $TARGET" >&2; exit 2 ;;
esac

for unit in ares-auction ares-rideshare ares-cohort-formation ares-cohort-weekly; do
    if systemctl is-active --quiet "$unit"; then
        echo "Stopping $unit"
        systemctl stop "$unit"
    fi
done

# Refuse to swap if the Fheya production unit is up — it would still
# be listening on the same hub endpoints.
if systemctl is-active --quiet ares-session 2>/dev/null; then
    echo "Refusing to swap: ares-session (Fheya) is still active."
    echo "Stop it first:  systemctl stop ares-session"
    exit 1
fi

echo "Starting ares-$TARGET"
systemctl start "ares-$TARGET"
systemctl --no-pager status "ares-$TARGET" | head -15
