# GCS-link impairment for PX4 SITL runs (docs/HARDWARE_FLIGHT_READINESS.md). Run as root with NET_ADMIN
# in the container that shares PX4's network namespace. Only UDP to/from 18570 is delayed, so the
# PX4 <-> Gazebo loopback traffic is untouched. Remove with: tc qdisc del dev lo root

set -e
tc qdisc del dev lo root 2>/dev/null || true
tc qdisc add dev lo root handle 1: prio
tc qdisc add dev lo parent 1:3 handle 30: netem delay 40ms 20ms loss 1%
tc filter add dev lo parent 1:0 protocol ip prio 1 u32 match ip protocol 17 0xff match ip dport 18570 0xffff flowid 1:3
tc filter add dev lo parent 1:0 protocol ip prio 1 u32 match ip protocol 17 0xff match ip sport 18570 0xffff flowid 1:3
tc qdisc show dev lo; tc filter show dev lo | head -4
