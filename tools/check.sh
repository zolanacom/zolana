#!/bin/sh
set -eu
task_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$task_root"
sh tools/dev.sh fmt --all -- --check
sh tools/dev.sh clippy --offline --locked --workspace --all-targets -- -D warnings
sh tools/dev.sh test --offline --locked --workspace -- --nocapture
python3 -B -m unittest discover -s tools -p '*_test.py'
git diff --check
