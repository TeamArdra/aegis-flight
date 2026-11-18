#!/usr/bin/env bash
# Run the AegisFlight ips-bridge ON the Pi with the SiK radio as GCS side and the laptop SITL as FC side.
#
#   LAPTOP_IP=192.168.1.20 MODE=advisory BAUD=57600 ./pi_bridge_run.sh start
#   ./pi_bridge_run.sh status | stop | kill
#
# Env (defaults in brackets):
#   LAPTOP_IP (required for start)   FC_PORT_NUM [5762]      BAUD [57600]       MODE passive|advisory|active-ips [passive]
#   GCS_PORT [by-id CP2102 path]     STATUS_PORT [8765]      SIGNING_KEY_FILE   MGMT_KEY_FILE   ALLOW_UNSIGNED=1
#   RUN_ROOT [~/aegis_runs]          REPO [~/aegis_test]     PYTHON [python3]   MONITOR=1|0 [1]   EXTRA_ARGS
# No sudo needed. Each start makes $RUN_ROOT/<timestamp>/ (bridge.log, pi_monitor.jsonl) and links $RUN_ROOT/current.
set -u

REPO="${REPO:-$HOME/aegis_test}"
RUN_ROOT="${RUN_ROOT:-$HOME/aegis_runs}"
PYTHON="${PYTHON:-python3}"
BAUD="${BAUD:-57600}"
MODE="${MODE:-passive}"
FC_PORT_NUM="${FC_PORT_NUM:-5762}"
STATUS_PORT="${STATUS_PORT:-8765}"
MONITOR="${MONITOR:-1}"
GCS_PORT="${GCS_PORT:-/dev/serial/by-id/usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0}"
PIDFILE="$RUN_ROOT/bridge.pid"
MONPIDFILE="$RUN_ROOT/monitor.pid"

die() { echo "pi_bridge_run: $*" >&2; exit 2; }

is_bridge_pid() {  # pid alive AND really an ips-bridge (guards against pid reuse)
    [ -n "${1:-}" ] && [ -r "/proc/$1/cmdline" ] && tr '\0' ' ' < "/proc/$1/cmdline" | grep -q 'ips-bridge'
}

read_pid() { [ -f "$1" ] && cat "$1" 2>/dev/null || true; }

latency_timer() {
    local real tty node cur
    real="$(readlink -f "$GCS_PORT" 2>/dev/null || true)"
    [ -n "$real" ] && [ -e "$real" ] || { echo "latency_timer: radio port $GCS_PORT not found"; return; }
    tty="$(basename "$real")"
    node="/sys/bus/usb-serial/devices/$tty/latency_timer"
    [ -e "$node" ] || { echo "latency_timer: $node missing (not a usb-serial device?)"; return; }
    cur="$(cat "$node" 2>/dev/null || echo '?')"
    if [ -w "$node" ] && echo 1 > "$node" 2>/dev/null; then
        echo "latency_timer: $tty set to 1 ms (was $cur ms)"
    else
        echo "latency_timer: NOT writable without root, stays $cur ms ($node)." \
             "One-time fix as root: echo 1 > $node, or a udev rule" \
             "'ACTION==\"add\", SUBSYSTEM==\"usb-serial\", DRIVER==\"cp210x\", ATTR{latency_timer}=\"1\"'"
    fi
}

cmd_start() {
    [ -n "${LAPTOP_IP:-}" ] || die "LAPTOP_IP is required (the laptop running SITL / FC TCP port $FC_PORT_NUM)"
    case "$MODE" in passive|advisory|active-ips) ;; *) die "MODE must be passive|advisory|active-ips, got '$MODE'" ;; esac
    [ -d "$REPO/src/aegisflight" ] || die "repo copy not found at $REPO (run laptop_ctl.py deploy)"
    [ -e "$GCS_PORT" ] || die "radio port $GCS_PORT not found (radio unplugged?)"
    mkdir -p "$RUN_ROOT"
    local old; old="$(read_pid "$PIDFILE")"
    if is_bridge_pid "$old"; then die "bridge already running (pid $old); run '$0 stop' first"; fi

    local run_dir; run_dir="$RUN_ROOT/$(date +%Y%m%d-%H%M%S)-$MODE"
    mkdir -p "$run_dir"
    ln -sfn "$run_dir" "$RUN_ROOT/current"

    local args=(ips-bridge --gcs-port "$GCS_PORT" --gcs-baud "$BAUD" --fc-port "socket://$LAPTOP_IP:$FC_PORT_NUM"
                --allow-url --defense-mode "$MODE" --status-port "$STATUS_PORT" --status-interval 5
                --signing-state "$run_dir/signing_state.json" --mgmt-state "$run_dir/mgmt_state.json"
                --audit-log "$run_dir/mgmt_audit.jsonl")
    if [ -n "${SIGNING_KEY_FILE:-}" ]; then
        [ -r "$SIGNING_KEY_FILE" ] || die "SIGNING_KEY_FILE $SIGNING_KEY_FILE not readable"
        args+=(--signing-key-file "$SIGNING_KEY_FILE")
    elif [ "$MODE" = active-ips ]; then
        [ "${ALLOW_UNSIGNED:-0}" = 1 ] || die "active-ips needs SIGNING_KEY_FILE (or ALLOW_UNSIGNED=1 to accept the risk)"
        args+=(--allow-unsigned)
    fi
    if [ -n "${MGMT_KEY_FILE:-}" ]; then
        [ -r "$MGMT_KEY_FILE" ] || die "MGMT_KEY_FILE $MGMT_KEY_FILE not readable"
        args+=(--mgmt-key-file "$MGMT_KEY_FILE")
    fi
    # shellcheck disable=SC2206
    [ -n "${EXTRA_ARGS:-}" ] && args+=($EXTRA_ARGS)

    {
        echo "run_dir=$run_dir"; echo "date=$(date -Is)"; echo "mode=$MODE baud=$BAUD fc=socket://$LAPTOP_IP:$FC_PORT_NUM"
        echo "signing=${SIGNING_KEY_FILE:+yes} mgmt_key=${MGMT_KEY_FILE:+yes}"
        echo "args=${args[*]}"; echo "throttled=$(vcgencmd get_throttled 2>/dev/null || echo n/a)"
    } > "$run_dir/run_info.txt"

    latency_timer | tee "$run_dir/latency_timer.txt"

    # SIGTERM/SIGINT -> KeyboardInterrupt so the bridge closes cleanly (background jobs inherit SIGINT=ignore)
    local boot='import signal,sys;h=signal.default_int_handler;signal.signal(signal.SIGINT,h);signal.signal(signal.SIGTERM,h);'
    boot+='from aegisflight.cli.main import main;sys.exit(main(sys.argv[1:]))'
    PYTHONPATH="$REPO/src${PYTHONPATH:+:$PYTHONPATH}" PYTHONUNBUFFERED=1 \
        nohup "$PYTHON" -c "$boot" "${args[@]}" > "$run_dir/bridge.log" 2>&1 < /dev/null &
    local pid=$!
    disown "$pid" 2>/dev/null || true
    echo "$pid" > "$PIDFILE"
    sleep 3
    if ! is_bridge_pid "$pid"; then
        echo "pi_bridge_run: bridge exited during startup; log tail:" >&2
        tail -n 15 "$run_dir/bridge.log" >&2
        rm -f "$PIDFILE"
        exit 1
    fi
    if [ "$MONITOR" = 1 ]; then
        nohup "$PYTHON" "$REPO/scripts/radio_test/pi_monitor.py" --pid "$pid" --out "$run_dir/pi_monitor.jsonl" \
            --status-url "http://127.0.0.1:$STATUS_PORT" > "$run_dir/pi_monitor.log" 2>&1 < /dev/null &
        echo $! > "$MONPIDFILE"
        disown $! 2>/dev/null || true
    fi
    echo "started: pid=$pid mode=$MODE baud=$BAUD run_dir=$run_dir status=http://127.0.0.1:$STATUS_PORT/status"
}

stop_monitor() {
    local m; m="$(read_pid "$MONPIDFILE")"
    if [ -n "$m" ] && [ -r "/proc/$m/cmdline" ] && tr '\0' ' ' < "/proc/$m/cmdline" | grep -q pi_monitor; then
        kill -TERM "$m" 2>/dev/null || true
        for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$m" 2>/dev/null || break; sleep 0.5; done
    fi
    rm -f "$MONPIDFILE"
}

cmd_stop() {
    local pid; pid="$(read_pid "$PIDFILE")"
    if is_bridge_pid "$pid"; then
        kill -TERM "$pid" 2>/dev/null || true
        for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
        if kill -0 "$pid" 2>/dev/null; then kill -KILL "$pid" 2>/dev/null || true; echo "bridge pid $pid needed SIGKILL"; fi
        echo "stopped bridge pid $pid"
    else
        echo "bridge not running"
    fi
    rm -f "$PIDFILE"
    stop_monitor
}

cmd_kill() {  # SIGKILL the bridge only (fault tests); the monitor keeps running and records the loss
    local pid; pid="$(read_pid "$PIDFILE")"
    if is_bridge_pid "$pid"; then
        kill -KILL "$pid" && echo "SIGKILLed bridge pid $pid"
    else
        echo "bridge not running"; exit 1
    fi
}

cmd_status() {
    local pid; pid="$(read_pid "$PIDFILE")"
    if is_bridge_pid "$pid"; then
        echo "running pid=$pid run_dir=$(readlink -f "$RUN_ROOT/current" 2>/dev/null)"
        "$PYTHON" - "$STATUS_PORT" <<'PY' || echo "status API not reachable"
import json, sys, urllib.request
try:
    st = json.load(urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/status", timeout=2))
except OSError:
    raise SystemExit(1)
print(json.dumps({k: st.get(k) for k in ("mode", "state", "frames", "latency_us", "topology")}))
PY
        echo "throttled=$(vcgencmd get_throttled 2>/dev/null || echo n/a) $(vcgencmd measure_temp 2>/dev/null || true)"
    else
        echo "not running"; exit 1
    fi
}

case "${1:-}" in
    start) cmd_start ;;
    stop) cmd_stop ;;
    kill) cmd_kill ;;
    status) cmd_status ;;
    *) echo "usage: $0 start|stop|status|kill   (env: LAPTOP_IP MODE BAUD SIGNING_KEY_FILE MGMT_KEY_FILE ...)" >&2; exit 2 ;;
esac
