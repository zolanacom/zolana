#!/bin/sh
# Run the program-level differential comparison of node/candidate/differential.
#
# usage: sh node/candidate/differential/run.sh [record|quick|controls]
#
#   record    (default) the four runs decision 0043 quotes, with its seeds and
#             sizes, then the figures of the four logs compared with
#             expected-figures.txt
#   quick     one short run against the pinned candidate: seed 1, 3 walks
#   controls  the negative controls: one deliberate change to one build at a
#             time, each of which must make the comparison fail
#
# Everything is written under target/differential (ignored by Git), or under
# $DIFFERENTIAL_SCRATCH if that is set. The build is offline, from the
# repository's lock file and the dependency cache that tools/dev.sh uses, and
# compiles the vendored runtime in node/agave once. See the README beside
# this file.
set -u
here="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
root="$(CDPATH= cd -- "$here/../../.." && pwd)"
scratch="${DIFFERENTIAL_SCRATCH:-$root/target/differential}"
mode="${1:-record}"
mkdir -p "$scratch/logs" || exit 2

# one NAME SEED WALKS [assemble.py options]
# Assembles the workspace "$scratch/NAME" and runs the comparison in it.
one() {
    name="$1"; seed="$2"; walks="$3"; shift 3
    variant="pinned"
    case "$*" in
        *--hardened*) variant="hardened" ;;
        *--candidate-on-workspace-protocol*) variant="shared-protocol" ;;
    esac
    log="$scratch/logs/$name.log"
    echo "== assemble.py $*" > "$log"
    if python3 -B "$here/assemble.py" --out "$scratch/$variant" "$@" >> "$log" 2>&1; then
        echo "== DIFFERENTIAL_SEED=$seed DIFFERENTIAL_WALKS=$walks cargo test --offline -p program-differential --test differential -- --nocapture" >> "$log"
        DIFFERENTIAL_SEED="$seed" DIFFERENTIAL_WALKS="$walks" sh "$root/tools/dev.sh" test --offline \
            --manifest-path "$scratch/$variant/Cargo.toml" --target-dir "$scratch/build" \
            -p program-differential --test differential -- --nocapture > "$scratch/$variant/run.raw" 2>&1
        code=$?
        # Cargo's progress lines and its notes about the unused parts of the
        # copied lock file and profiles are left out of the log.
        grep -v '^ *Compiling\|^ *Blocking\|^warning: patch\|^warning: profile\|^help: Check\|^      with the dep\|^      what is locked\|^      version. This' \
            "$scratch/$variant/run.raw" >> "$log"
    else
        code=2
    fi
    echo "== exit=$code" >> "$log"
    echo "$name: $(grep '^test result:\|^assemble:\|^error' "$log" | head -1)"
    [ "$code" = 0 ]
}

case "$mode" in
    record)
        failed=0
        one pinned-candidate-seed1 1 1000 || failed=1
        one pinned-candidate-seed2 2 250 || failed=1
        one hardened-candidate-seed3 3 250 --hardened || failed=1
        one candidate-program-on-workspace-protocol-seed4 4 250 --candidate-on-workspace-protocol || failed=1
        if [ "$failed" != 0 ]; then
            echo "a run failed; see $scratch/logs" >&2
            exit 1
        fi
        python3 -B "$here/figures.py" \
            "$scratch/logs/pinned-candidate-seed1.log" \
            "$scratch/logs/pinned-candidate-seed2.log" \
            "$scratch/logs/hardened-candidate-seed3.log" \
            "$scratch/logs/candidate-program-on-workspace-protocol-seed4.log" \
            > "$scratch/logs/figures.txt" || exit 1
        cat "$scratch/logs/figures.txt"
        if cmp -s "$scratch/logs/figures.txt" "$here/expected-figures.txt"; then
            echo "figures equal expected-figures.txt"
        else
            echo "figures DIFFER from expected-figures.txt:" >&2
            diff "$here/expected-figures.txt" "$scratch/logs/figures.txt" >&2
            exit 1
        fi
        ;;
    quick)
        one quick-pinned-candidate-seed1 1 3 || { echo "the run failed; see $scratch/logs" >&2; exit 1; }
        sed -n '/^fixed edge cases/p;/^seed /p;/instructions gave the same/p' "$scratch/logs/quick-pinned-candidate-seed1.log"
        ;;
    controls)
        python3 -B "$here/negative_controls.py" "$scratch" 2>&1 | tee "$scratch/logs/negative-controls.log"
        tail -1 "$scratch/logs/negative-controls.log" | grep -q '^7 of 7 deliberate differences detected$'
        ;;
    *)
        echo "usage: sh node/candidate/differential/run.sh [record|quick|controls]" >&2
        exit 2
        ;;
esac
