# Path-remapped development wallet builds

This workflow creates local native-wallet candidates without compiling or starting a validator, publishing anything, changing the installed service or overwriting `target/debug/native-wallet`. It uses the existing offline dependency cache, new source/target roots and one low-priority compiler job. It requires the pinned Rust 1.92.0 Apple-arm64 toolchain, macOS command-line tools and Python; other build hosts/targets are not implemented by this recipe.

Build into a **new** output directory whose parent already exists:

```sh
python3 -B tools/wallet_build.py --output /private/tmp/new-wallet-build
```

The builder snapshots only native workspace inputs and records their relative names/content, including executable bits and safe relative symlinks. `.git`, private fixtures/wallets, existing target directories and dependency caches are not copied. The existing Cargo cache is read using the pinned lockfile; Cargo runs `--offline --locked` with a separate target directory. No Rustup/dependency installation or network fetch occurs. Rust/native compiler work runs with nice level 15, one Cargo/native build job, one Rust codegen unit and bounded timeout. Default timeout is one hour; `--timeout` accepts 60–7,200 seconds. Signal/timeout cleanup stops only its owned compiler process group and retains private evidence. This limits peak parallelism; compilation still consumes CPU.

`wallet-release` inherits Cargo's release profile with optimization level 2, no debug symbols/incremental build, one codegen unit, no LTO and stripped symbols. The recipe retains ordinary unwind behavior. It sets source/Cargo/toolchain/build/temp/home remaps through `CARGO_ENCODED_RUSTFLAGS`, preserving spaces, and equivalent native file/debug mappings through shell-escaped C/C++ flags. More specific prefixes follow broad ones. The recipe also fixes its timestamp environment and disables the Mach-O linker UUID. Rust documents [path remapping and its external-tool/linker limits](https://doc.rust-lang.org/rustc/remap-source-paths.html) and Cargo documents [custom profiles](https://doc.rust-lang.org/cargo/reference/profiles.html). Compiler flags alone are insufficient evidence; the finished bytes must pass inspection.

Before the wallet build, actual compiled probes check Rust `file!`, panic-location output and native C `__FILE__`, then inspect probe binaries/output. Finished-wallet checks scan configured roots in UTF-8 and UTF-16, reject generic personal/temporary prefixes, and inspect actual load commands. Only system dynamic libraries are permitted; rpaths, debug segments and UUID commands are refused. The expected native signature is the linker's ad-hoc signature with no team identity. No Developer ID, trust-store change or notarization is requested. A remapping failure cannot be repaired by silently replacing text in executable bytes.

Successful output includes:

- `native-wallet`: the inspected candidate, separate from debug/client installations.
- `BUILD.json`: secret-free binary/source/lockfile/compiler/recipe/probe/inspection receipt.
- `state.json`, private `build.log`, source snapshot, target cache and probe files: operator evidence, **not package inputs**.

Only the candidate and reviewed receipt feed packaging. Build logs, source paths, environment mappings containing actual host paths and intermediate artifacts are not shipped. The receipt exports canonical prefixes and digests, not the original path values. Keep the whole operator root private; preserve failed roots instead of reusing them. Existing outputs are refused. Source changes during snapshot creation or before packaging require a fresh candidate/review. Documentation-only changes outside native inputs do not invalidate its native-source digest.

Run native library checks against that same snapshot and optimized profile:

```sh
python3 -B tools/wallet_build.py --output /private/tmp/new-wallet-build --tests
```

This validates snapshot/binary identity, then runs wallet and payment library tests offline with one test thread/job and the same remaps/profile. New `TESTS.json`, `tests-state.json` and private `tests.log` record the result. It does not start validators or perform real payments. Test-only loopback servers/new temporary wallet state are owned by the tests. A partial or failed test is retained; a repeated test log is not silently overwritten.

Build again at a distinct new location to assess location dependence. Use different path lengths/spaces, not a reused target cache. Compare native source/lock/compiler identities and actual binary digests. Even matching local repeats do not prove cross-host reproducibility or absence of every possible identifying value; the scanner addresses the specified path encodings/prefixes. It does not establish team/account/network anonymity or remove required copyright/license information.

Package the inspected candidate with the unchanged public tester profile:

```sh
python3 -B tools/package_wallet.py \
  --network /private/public-profile.json --label 'Reviewed local testnet' \
  --rpc https://127.0.0.1:23898 --transport https \
  --faucet https://127.0.0.1:13780 --invite-only \
  --local-tls-ca /private/public-local-ca.crt \
  --binary /private/tmp/new-wallet-build/native-wallet \
  --build-receipt /private/tmp/new-wallet-build/BUILD.json \
  --output /private/new-remapped-wallet.tar.gz
```

Use the actual existing profile label/endpoints/public CA; the example does not configure hosting. Receipt/binary/native-source validation happens before executing the local candidate for offline public-profile validation. Packaging scans every input file and preserves all upstream/dependency notices. A receipt does not approve an arbitrary binary with a matching filename. A missing/mismatched/stale receipt refuses the build claim; omitting it produces the legacy `local-development` package without a remapping claim.

The new manifest kind is `path-remapped-development`, still under the existing bundle/descriptor formats. `BUILD.json` is in the exact signed file inventory, bound by the manifest and archive. Use the updated independently reviewed `wallet_release.py` verifier from the [authenticated-release runbook](wallet-release-runbook.md); an older verifier fails closed on the new kind. Independent verifier/publisher/profile pins, release sequence protection and pending-update recovery all still apply. A valid receipt/signature cannot silently change a wallet's network profile or migrate its data.

Repeat standalone acceptance without any compiler or validator startup:

```sh
python3 -B tools/wallet_release_rehearsal.py --build-root /private/tmp/new-wallet-build
```

The bounded runner creates only new rehearsal signing keys and encrypted wallets, packages/rebuilds byte-identical archives, audits every file, and tests signed verification/install under system Python, isolated wallet serving, inherited locking after runner death, four installer SIGKILL points, changed signed contents and offline encrypted restore. Existing original wallets and protected service files are never opened. Synthetic pending/staging sentinels check installer preservation; they do not replace prior live payment/nullifier evidence. Result pointers are `.local/remap-036-stage.json` and `.local/remap-036-result.json`. See LOCAL-036 validation.

This remains a local development build. Production key custody/distribution, Apple Developer signing/notarization, independent runtime/cryptographic review, supported-platform/physical-device acceptance and actual hosted services remain separate launch gates. Do not call the toolchain's ad-hoc signature an Apple identity or the publisher signature an audit.
