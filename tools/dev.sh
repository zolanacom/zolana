#!/bin/sh
set -eu
task_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
export CARGO_HOME="$task_root/.tools/cargo"
export CARGO_TARGET_DIR="$task_root/target"
# Keep native-library artifacts lean and consistent across build/test commands.
: "${CXXFLAGS:=-g0}"
export CXXFLAGS
# Apple's command-line tools ship libclang outside dyld's fallback directories.
if [ "$(uname -s)" = Darwin ]; then
    task_clang_dir="$(xcode-select -p)/usr/lib"
    if [ -f "$task_clang_dir/libclang.dylib" ]; then
        : "${LIBCLANG_PATH:=$task_clang_dir}"
        export LIBCLANG_PATH
        export DYLD_FALLBACK_LIBRARY_PATH="$LIBCLANG_PATH${DYLD_FALLBACK_LIBRARY_PATH:+:$DYLD_FALLBACK_LIBRARY_PATH}"
    fi
fi
# Some validator dependencies generate protobuf code in their own build scripts.
# Reuse the cached host compiler without requiring a system installation.
if [ -z "${PROTOC:-}" ]; then
    task_protoc_host=""
    case "$(uname -s)-$(uname -m)" in
        Darwin-arm64) task_protoc_host="macos-aarch_64" ;;
        Darwin-x86_64) task_protoc_host="macos-x86_64" ;;
        Linux-aarch64) task_protoc_host="linux-aarch_64" ;;
        Linux-x86_64) task_protoc_host="linux-x86_64" ;;
    esac
    if [ -n "$task_protoc_host" ]; then
        for task_protoc in "$CARGO_HOME"/registry/src/*/protoc-bin-vendored-"$task_protoc_host"-*/bin/protoc; do
            if [ -x "$task_protoc" ]; then
                export PROTOC="$task_protoc"
                export PROTOC_INCLUDE="$(dirname -- "$(dirname -- "$task_protoc")")/include"
                break
            fi
        done
    fi
fi
cd "$task_root"
exec cargo "$@"
