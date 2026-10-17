#!/bin/sh
set -eu
task_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$task_root"
CARGO_BUILD_JOBS=2 sh tools/dev.sh build --offline --locked --no-default-features \
    -p agave-validator -p native-localnet --bin agave-validator --bin native-localnet
