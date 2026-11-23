#!/usr/bin/env bash
# Apply realistic telemetry-radio link impairments inside the Linux bench container:
# latency jitter, burst packet loss, packet reordering, corruption, and bandwidth cap.
set -euo pipefail

IFACE="${1:-eth0}"
DELAY="${NETEM_DELAY:-40ms}"
JITTER="${NETEM_JITTER:-20ms}"
LOSS="${NETEM_LOSS:-3%}"
LOSS_CORR="${NETEM_LOSS_CORR:-25%}"
REORDER="${NETEM_REORDER:-4%}"
CORRUPT="${NETEM_CORRUPT:-0.2%}"
RATE="${NETEM_RATE:-115200bit}"

if ! command -v tc >/dev/null 2>&1; then
  echo "tc (iproute2) is required inside a Linux container or host" >&2
  exit 2
fi

tc qdisc del dev "$IFACE" root 2>/dev/null || true
tc qdisc add dev "$IFACE" root handle 1: tbf rate "$RATE" burst 4096 latency 400ms
tc qdisc add dev "$IFACE" parent 1:1 handle 10: netem \
  delay "$DELAY" "$JITTER" distribution normal \
  loss "$LOSS" "$LOSS_CORR" \
  reorder "$REORDER" 50% \
  corrupt "$CORRUPT"

echo "Applied netem on $IFACE: rate=$RATE delay=$DELAY±$JITTER loss=$LOSS($LOSS_CORR) reorder=$REORDER corrupt=$CORRUPT"
tc qdisc show dev "$IFACE"
