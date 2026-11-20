#!/bin/sh
# Build the browser wallet core (clients/browser-core) to WebAssembly and
# generate its JavaScript bindings.
#
#     sh sdk/build-browser-core.sh
#
# Output: clients/browser-core/pkg/browser_core.js and browser_core_bg.wasm
# (plus the .d.ts files wasm-bindgen writes). That directory is git-ignored.
#
# This builds the single-threaded package only. The threaded package is the
# `browser-multicore` feature; it needs shared Wasm memory and atomics, and the
# repository does not record the compiler flags for it, so it is not built here.
#
# Prerequisites, none of which this script installs:
#   1. Dependencies fetched once:      sh tools/dev.sh fetch --locked
#   2. The Wasm target for the pinned Rust toolchain (rust-toolchain.toml):
#                                      rustup target add wasm32-unknown-unknown
#   3. The wasm-bindgen command-line tool in PATH, at exactly the version of the
#      `wasm-bindgen` dependency pinned in clients/browser-core/Cargo.toml.
#      The generated bindings only work with a matching tool version.
#
# Where each step comes from:
#   - target and tool: docs/refactoring-plan.md ("Browser Wasm compilation")
#   - package and library name: clients/browser-core/Cargo.toml
#   - `--target web`: the workers load the output with
#     `await import("/wasm/browser_core.js")` and call its default export
#   - output directory and file names: .gitignore and tools/browser_feasibility.py
set -eu
task_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$task_root"

[ "$#" -eq 0 ] || { printf 'Usage: sh sdk/build-browser-core.sh\n' >&2; exit 2; }

pinned="$(sed -n 's/^wasm-bindgen = "=\([0-9.]*\)"$/\1/p' clients/browser-core/Cargo.toml)"
[ -n "$pinned" ] || { printf 'Cannot read the wasm-bindgen pin from clients/browser-core/Cargo.toml\n' >&2; exit 1; }

command -v wasm-bindgen >/dev/null 2>&1 || {
    printf 'wasm-bindgen %s is required in PATH; it is not installed by this script.\n' "$pinned" >&2
    exit 1
}
found="$(wasm-bindgen --version | sed -n 's/^wasm-bindgen \([0-9.]*\).*$/\1/p')"
[ "$found" = "$pinned" ] || {
    printf 'wasm-bindgen %s found, but clients/browser-core pins %s.\n' "$found" "$pinned" >&2
    exit 1
}
[ -d "$(rustc --print sysroot)/lib/rustlib/wasm32-unknown-unknown" ] || {
    printf 'The wasm32-unknown-unknown target is not installed for %s.\n' "$(rustc --version)" >&2
    printf 'Install it with: rustup target add wasm32-unknown-unknown\n' >&2
    exit 1
}

sh tools/dev.sh build --offline --locked --release \
    --target wasm32-unknown-unknown -p zolana-browser-core --lib

out="clients/browser-core/pkg"
wasm-bindgen --target web --out-dir "$out" \
    target/wasm32-unknown-unknown/release/browser_core.wasm

printf 'Built with %s and wasm-bindgen %s:\n' "$(rustc --version)" "$found"
for name in browser_core.js browser_core_bg.wasm; do
    [ -f "$out/$name" ] || { printf 'Missing output %s\n' "$out/$name" >&2; exit 1; }
    printf '  %s  %s bytes\n' "$out/$name" "$(wc -c < "$out/$name" | tr -d ' ')"
done
