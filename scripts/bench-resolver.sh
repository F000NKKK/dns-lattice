#!/usr/bin/env bash
# Resolver benchmarks: dns-lattice measured next to hickory 0.26.x
# (bench/resolver, a standalone workspace outside the published crates).
#
# Usage:
#   scripts/bench-resolver.sh micro [--bench NAME] [--warm-up S]
#                                   [--measurement S]
#                                   [--save-baseline NAME | --baseline NAME]
#                                   [--out DIR] [-- CRITERION_ARGS...]
#       Unprivileged, any platform. Runs the criterion micro-benchmarks
#       (codec, name, matcher, cache; only NAME with --bench) with plots
#       disabled. --warm-up and --measurement set criterion's warm-up and
#       measurement time in seconds (criterion defaults: 3 and 5).
#       --save-baseline / --baseline store or compare against a named
#       criterion baseline, for before/after comparisons on one machine.
#       With --out, the console output goes to DIR/micro.log as well, and
#       every criterion/<benchmark>/new/estimates.json is copied below
#       DIR/criterion/. Arguments after `--` go to criterion unchanged
#       (for example a benchmark name filter).
#
#   scripts/bench-resolver.sh build
#       Builds the responder, dl-client and hk-client in release mode.
#
#   scripts/bench-resolver.sh run [--variants LIST] [--variants-file FILE]
#                                 [--reps N] [--duration S] [--warmup S]
#                                 [--concurrency N] [--latency-us US]
#                                 [--out DIR] [--no-pin]
#       Linux. Unprivileged, loopback only. For every row of
#       bench/resolver/variants.tsv selected by LIST (comma-separated row ids
#       or groups; default all), starts the responder (upstream TTL 0 for cold
#       rows, 3600 for warm rows) and runs dl-client and hk-client against it,
#       N times each (default 3), alternating which goes first. With 4 or
#       more CPUs and taskset, clients and responder are pinned to disjoint
#       halves. DIR (default $CARGO_TARGET_DIR/results/<UTC time>) receives
#       meta.json (commit, toolchain, resolved versions) and, per row and
#       repetition, dl.json, hk.json and responder-<library>.json. The exit
#       status is non-zero if any run was invalid or failed. Run `build`
#       first.
#
# Builds go to $CARGO_TARGET_DIR, default target/bench-resolver.

set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MANIFEST="$ROOT/bench/resolver/Cargo.toml"
TARGET_DIR=${CARGO_TARGET_DIR:-$ROOT/target/bench-resolver}
BENCHES=(codec name matcher cache)

log() {
    printf '[bench-resolver] %s\n' "$*" >&2
}

die() {
    log "error: $*"
    exit 1
}

usage() {
    sed -n '2,/^$/s/^# \{0,1\}//p' "${BASH_SOURCE[0]}" >&2
    exit 64
}

need_value() {
    [[ $# -ge 2 && -n $2 ]] || die "$1 needs a value"
}

# ---------------------------------------------------------------- micro ---

cmd_micro() {
    local bench="" warmup="" measurement="" save="" baseline="" out=""
    local -a extra=()
    while [[ $# -gt 0 ]]; do
        case $1 in
            --bench) need_value "$@"; bench=$2; shift 2 ;;
            --warm-up) need_value "$@"; warmup=$2; shift 2 ;;
            --measurement) need_value "$@"; measurement=$2; shift 2 ;;
            --save-baseline) need_value "$@"; save=$2; shift 2 ;;
            --baseline) need_value "$@"; baseline=$2; shift 2 ;;
            --out) need_value "$@"; out=$2; shift 2 ;;
            --) shift; extra=("$@"); break ;;
            -h | --help) usage ;;
            *) die "unknown micro option: $1" ;;
        esac
    done
    [[ -z $save || -z $baseline ]] || die "--save-baseline and --baseline are exclusive"

    local -a cargo_args=(bench --manifest-path "$MANIFEST")
    if [[ -n $bench ]]; then
        local known=0 name
        for name in "${BENCHES[@]}"; do
            [[ $name == "$bench" ]] && known=1
        done
        [[ $known == 1 ]] || die "unknown benchmark '$bench' (one of: ${BENCHES[*]})"
        cargo_args+=(--bench "$bench")
    else
        for name in "${BENCHES[@]}"; do
            cargo_args+=(--bench "$name")
        done
    fi

    local -a criterion_args=(--noplot)
    [[ -z $warmup ]] || criterion_args+=(--warm-up-time "$warmup")
    [[ -z $measurement ]] || criterion_args+=(--measurement-time "$measurement")
    [[ -z $save ]] || criterion_args+=(--save-baseline "$save")
    [[ -z $baseline ]] || criterion_args+=(--baseline "$baseline")
    # Guarded: expanding an empty array trips `set -u` on bash 3.2 (macOS).
    if [[ ${#extra[@]} -gt 0 ]]; then
        criterion_args+=("${extra[@]}")
    fi

    export CARGO_TARGET_DIR="$TARGET_DIR"
    log "cargo ${cargo_args[*]} -- ${criterion_args[*]}"
    if [[ -z $out ]]; then
        cargo "${cargo_args[@]}" -- "${criterion_args[@]}"
        return
    fi

    mkdir -p "$out"
    cargo "${cargo_args[@]}" -- "${criterion_args[@]}" 2>&1 | tee "$out/micro.log"

    local estimates copied=0 rel
    while IFS= read -r -d '' estimates; do
        rel=${estimates#"$TARGET_DIR/criterion/"}
        mkdir -p "$out/criterion/$(dirname "$rel")"
        cp "$estimates" "$out/criterion/$rel"
        copied=$((copied + 1))
    done < <(find "$TARGET_DIR/criterion" -path '*/new/estimates.json' -print0)
    log "copied $copied estimates.json files to $out/criterion"
}

# ---------------------------------------------------------------- build ---

cmd_build() {
    export CARGO_TARGET_DIR="$TARGET_DIR"
    log "cargo build --release --bins"
    cargo build --release --manifest-path "$MANIFEST" --bins
}

# ------------------------------------------------------------------ run ---

RESPONDER_PID=""
RESPONDER_FD=""
WORK_DIR=""

stop_responder() {
    if [[ -n $RESPONDER_FD ]]; then
        # Closing the responder's stdin makes it write its counters and exit.
        eval "exec ${RESPONDER_FD}>&-"
        RESPONDER_FD=""
    fi
    if [[ -n $RESPONDER_PID ]]; then
        wait "$RESPONDER_PID" 2>/dev/null || true
        RESPONDER_PID=""
    fi
}

cleanup() {
    if [[ -n $RESPONDER_PID ]]; then
        kill -TERM "$RESPONDER_PID" 2>/dev/null || true
    fi
    stop_responder
    if [[ -n $WORK_DIR ]]; then
        rm -rf "$WORK_DIR"
    fi
}

# json_port FILE NAME: the number after "NAME": in a compact JSON line.
json_port() {
    sed -n "s/.*\"$2\":\([0-9][0-9]*\).*/\1/p" "$1" | head -n 1
}

# start_responder TTL LATENCY_US COUNTERS_FILE: sets READY_FILE and CA_FILE.
start_responder() {
    local ttl=$1 latency=$2 counters=$3
    READY_FILE="$WORK_DIR/ready.json"
    CA_FILE="$WORK_DIR/ca.der"
    : >"$READY_FILE"
    local fifo
    fifo=$(mktemp -u "$WORK_DIR/stdin.XXXXXX")
    mkfifo "$fifo"
    exec {RESPONDER_FD}<>"$fifo"
    "${RESPONDER_PIN[@]}" "$BIN/responder" --ca-out "$CA_FILE" --ttl "$ttl" \
        --latency-us "$latency" --out "$counters" <"$fifo" >"$READY_FILE" {RESPONDER_FD}>&- &
    RESPONDER_PID=$!
    rm -f "$fifo"
    local waited=0
    until [[ -s $READY_FILE ]]; do
        kill -0 "$RESPONDER_PID" 2>/dev/null || die "the responder exited before it was ready"
        sleep 0.1
        waited=$((waited + 1))
        [[ $waited -lt 100 ]] || die "the responder did not become ready in 10 s"
    done
}

cmd_run() {
    local variants="$ROOT/bench/resolver/variants.tsv" select="" reps=3
    local duration=8 warmup=2 concurrency=16 latency=200 out="" pin=1
    while [[ $# -gt 0 ]]; do
        case $1 in
            --variants) need_value "$@"; select=$2; shift 2 ;;
            --variants-file) need_value "$@"; variants=$2; shift 2 ;;
            --reps) need_value "$@"; reps=$2; shift 2 ;;
            --duration) need_value "$@"; duration=$2; shift 2 ;;
            --warmup) need_value "$@"; warmup=$2; shift 2 ;;
            --concurrency) need_value "$@"; concurrency=$2; shift 2 ;;
            --latency-us) need_value "$@"; latency=$2; shift 2 ;;
            --out) need_value "$@"; out=$2; shift 2 ;;
            --no-pin) pin=0; shift ;;
            -h | --help) usage ;;
            *) die "unknown run option: $1" ;;
        esac
    done
    [[ -f $variants ]] || die "no variants file: $variants"
    [[ $reps =~ ^[0-9]+$ && $reps -ge 1 ]] || die "--reps must be a positive integer"

    BIN="$TARGET_DIR/release"
    [[ -x $BIN/responder && -x $BIN/dl-client && -x $BIN/hk-client ]] ||
        die "binaries missing in $BIN; run: scripts/bench-resolver.sh build"
    [[ -n $out ]] || out="$TARGET_DIR/results/$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$out"
    WORK_DIR=$(mktemp -d)
    trap cleanup EXIT
    trap 'exit 130' INT TERM

    # With enough CPUs the clients and the responder run on disjoint halves,
    # so the upstream never competes with the code under test.
    RESPONDER_PIN=()
    local -a client_pin=()
    local client_workers=""
    local cpus
    cpus=$(nproc 2>/dev/null || echo 1)
    if [[ $pin == 1 && $cpus -ge 4 ]] && command -v taskset >/dev/null 2>&1; then
        local half=$((cpus / 2))
        client_pin=(taskset -c "0-$((half - 1))")
        RESPONDER_PIN=(taskset -c "$half-$((cpus - 1))")
        client_workers=$half
        log "pinned: clients on CPUs 0-$((half - 1)), responder on $half-$((cpus - 1))"
    else
        log "not pinned (needs --no-pin unset, taskset and 4 or more CPUs)"
    fi

    {
        printf '{\n'
        printf '  "git_commit": "%s",\n' "$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
        printf '  "git_dirty": %s,\n' "$([[ -n $(git -C "$ROOT" status --porcelain 2>/dev/null) ]] && echo true || echo false)"
        printf '  "rustc": "%s",\n' "$(rustc --version 2>/dev/null || echo unknown)"
        printf '  "kernel": "%s",\n' "$(uname -sr)"
        printf '  "cpus": %s,\n' "$cpus"
        printf '  "reps": %s, "duration_s": %s, "warmup_s": %s,\n' "$reps" "$duration" "$warmup"
        printf '  "latency_us": %s, "default_concurrency": %s,\n' "$latency" "$concurrency"
        printf '  "pinned": %s,\n' "$([[ ${#client_pin[@]} -gt 0 ]] && echo true || echo false)"
        printf '  "resolved": [\n'
        (cd "$ROOT/bench/resolver" && cargo tree --prefix none --depth 1 2>/dev/null) |
            grep -E '^(hickory|dns-lattice|rustls|quinn|tokio) ' | sort -u |
            sed 's/.*/    "&",/' | sed '$ s/,$//'
        printf '  ]\n}\n'
    } >"$out/meta.json"
    log "meta: $out/meta.json"

    local failed=0 ran=0 id group proto mix cache conc
    while IFS=$'\t' read -r id group proto mix cache conc; do
        [[ -z $id || $id == \#* ]] && continue
        if [[ -n $select ]]; then
            local wanted=0 token
            for token in ${select//,/ }; do
                [[ $token == "$id" || $token == "$group" ]] && wanted=1
            done
            [[ $wanted == 1 ]] || continue
        fi
        [[ $conc != 0 ]] || conc=$concurrency
        local ttl=0
        [[ $cache == warm ]] && ttl=3600
        local rep lib
        for ((rep = 1; rep <= reps; rep++)); do
            # Alternate which library goes first so drift does not favor one.
            local -a order=(dl hk)
            [[ $((rep % 2)) -eq 0 ]] && order=(hk dl)
            for lib in "${order[@]}"; do
                local dir="$out/$id/rep$rep"
                mkdir -p "$dir"
                start_responder "$ttl" "$latency" "$dir/responder-$lib.json"
                local port stats
                port=$(json_port "$READY_FILE" "$proto")
                stats=$(json_port "$READY_FILE" stats)
                [[ -n $port && -n $stats ]] || die "no ports in the responder ready line"
                local -a extra=()
                [[ -z $client_workers ]] || extra=(--workers "$client_workers")
                log "$id rep $rep $lib"
                local status=0
                "${client_pin[@]}" "$BIN/$lib-client" --proto "$proto" --port "$port" \
                    --ca "$CA_FILE" --mix "$mix" --cache "$cache" --concurrency "$conc" \
                    --warmup "$warmup" --duration "$duration" --stats-port "$stats" \
                    "${extra[@]}" --out "$dir/$lib.json" || status=$?
                stop_responder
                ran=$((ran + 1))
                if [[ $status -ne 0 ]]; then
                    failed=$((failed + 1))
                    log "$id rep $rep $lib: exit status $status (see $dir/$lib.json)"
                fi
            done
        done
    done <"$variants"
    [[ $ran -gt 0 ]] || die "no variant matched '$select'"
    log "$ran runs, $failed invalid or failed; results in $out"
    [[ $failed -eq 0 ]]
}

# ----------------------------------------------------------------- main ---

[[ $# -ge 1 ]] || usage
command=$1
shift
case $command in
    micro) cmd_micro "$@" ;;
    build) cmd_build "$@" ;;
    run) cmd_run "$@" ;;
    -h | --help) usage ;;
    *) die "unknown command: $command" ;;
esac
