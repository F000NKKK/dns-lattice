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

# ----------------------------------------------------------------- main ---

[[ $# -ge 1 ]] || usage
command=$1
shift
case $command in
    micro) cmd_micro "$@" ;;
    -h | --help) usage ;;
    *) die "unknown command: $command" ;;
esac
