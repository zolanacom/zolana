#!/bin/sh
set -eu
task_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$task_root"

case "$#:${1-}" in
    0:) publication_check=yes ;;
    1:--development-only) publication_check=no ;;
    *) printf 'Usage: %s [--development-only]\n' "$0" >&2; exit 2 ;;
esac

# The publication check is not in this repository: say so before the long build.
if [ "$publication_check" = yes ] && [ ! -f tools/check_publication.py ]; then
    printf '%s\n' 'tools/check_publication.py is not in this repository, so the publication check cannot run.' \
        'Run the development checks with: sh tools/check.sh --development-only' >&2
    exit 2
fi

# Format workspace members only. Cargo fmt --all also visits local vendor dependencies.
sh tools/dev.sh fmt \
    -p native-payments -p payment-lab -p native-wallet -p native-wallet-seed \
    -p native-wallet-core -p zolana-browser-core -p native-payment-program \
    -p native-validator-check -p native-localnet -p native-rpc-access -- --check
CARGO_BUILD_JOBS=2 sh tools/dev.sh clippy --offline --locked --workspace --all-targets --no-deps -- -D warnings
CARGO_BUILD_JOBS=2 sh tools/dev.sh test --offline --locked --workspace -- --nocapture
# Python integration fixtures execute these binaries through their normal CLI.
CARGO_BUILD_JOBS=2 sh tools/dev.sh build --offline --locked --workspace --bins
# Lifecycle fixtures also pin the upstream validator CLI through this builder.
sh tools/build_localnet.sh
python3 -B -m unittest discover -s tools -p '*_test.py'
node --test clients/browser-wallet/*.test.mjs clients/network-portal/*.test.mjs
node clients/wallet-ui/ui-state.test.cjs
node tools/wallet_ui_contract_test.cjs
git diff --check
if [ "$publication_check" = yes ]; then
    python3 -B tools/check_publication.py
fi
