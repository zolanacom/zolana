#!/bin/sh
set -eu
task_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
export CARGO_HOME="$task_root/.tools/cargo"
export CARGO_TARGET_DIR="$task_root/target"
cd "$task_root"
exec cargo "$@"
