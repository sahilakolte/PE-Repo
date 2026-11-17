#!/usr/bin/env bash
# Starts every NF named on the `chain` line(s) of chain.conf, in the
# background, and stops them all on Ctrl+C. Each NF still registers with
# the monitor on its own; start order does not matter.
set -u
CONF="${1:-chain.conf}"
cd "$(dirname "$0")"

NFS=$(awk '{sub(/#.*/, "")} $1=="chain" || $1=="nf" {for (i = 2; i <= NF; i++) print $i}' "$CONF")
[ -n "$NFS" ] || { echo "no NFs in $CONF"; exit 1; }

pids=()
for nf in $NFS; do
    [ -x "./$nf" ] || { echo "./$nf not built (is $nf.c there? run make)"; kill "${pids[@]}" 2>/dev/null; exit 1; }
    "./$nf" &
    pids+=($!)
done

trap 'kill -INT "${pids[@]}" 2>/dev/null' INT TERM
wait
