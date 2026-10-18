#!/bin/sh
set -eu
task_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$task_root"
sh tools/dev.sh fmt -p native-payments -p payment-lab -p native-wallet -p native-payment-program -p native-validator-check -p native-localnet -p native-rpc-access -- --check
CARGO_BUILD_JOBS=2 sh tools/dev.sh clippy --offline --locked --workspace --all-targets --no-deps -- -D warnings
CARGO_BUILD_JOBS=2 sh tools/dev.sh test --offline --locked --workspace -- --nocapture
python3 -B -m unittest discover -s tools -p '*_test.py'
git diff --check
