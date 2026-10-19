# Authenticated offline wallet releases and recoverable updates

Use this workflow to prepare and rehearse signed standalone wallet downloads locally. No upload, public release, production publisher identity, Apple certificate or hosted network is created. It accepts `local-development` and the separately inspected `path-remapped-development` kind. The [path-remapped builder](path-remapped-wallet-runbook.md) prepares the latter with a signed-inventory build receipt. Production release review, Apple signing/notarization and key custody remain separate gates.

The trust bootstrap matters: obtain the reviewed `wallet_release.py` verifier and publisher fingerprint independently of the downloaded wallet. A verifier or public key supplied only alongside a replaced archive can also be replaced. This source tool is standalone, uses Python 3.9+ plus `/usr/bin/openssl`, and does not import another project module. Running the wallet still requires Python 3.10+ and its supported host platform. Retain/review the verifier SHA-256 through a trusted channel. No automated downloader or trust-on-first-use is installed.

The signing algorithm is P-256 ECDSA with SHA-256 via the operating system OpenSSL/LibreSSL executable, with an explicit domain prefix. The pinned key identity is SHA-256 of canonical named-curve public SubjectPublicKeyInfo DER, not PEM text. OpenSSL documents [digest signing and signature verification](https://docs.openssl.org/3.0/man1/openssl-dgst/) and [public-key export](https://docs.openssl.org/3.0/man1/openssl-pkey/). The local suite exercises the installed LibreSSL implementation; it implements no new cryptographic primitives.

Keep signing keys outside the download and installation, owned by their operator at 0600. Provision production custody separately. A local rehearsal can generate a new disposable named-curve key in a new private directory; the automated rehearsal does this without displaying it. The signer accepts an existing encrypted PEM key with `--password-file`, an owner-only bounded file. Passwords never appear in command arguments or environment variables. Neither test credentials nor a production private key belong in Git.

Create the existing allowlisted deterministic archive with `tools/package_wallet.py`. Preserve notices and the exact reviewed public profile. The signed descriptor binds both archive bytes and the embedded manifest/profile, platform, channel, sequence and source commit. Changing a label, endpoint, CA or network changes the profile pin; it requires a separately reviewed trust migration rather than an ordinary update. No wallet runtime is executed to verify a downloaded release.

For a remapped candidate, supply both the builder's `native-wallet` and `--build-receipt BUILD.json` when packaging. Receipt/binary/current native-source mismatch fails before the candidate's offline profile parser runs. The updated verifier requires the receipt in the manifest and validates its binary binding and declared inspection policy. Older trusted verifiers refuse this new kind; obtain/review the updated verifier independently before using it. A receipt is not a compiler attestation or independent security review.

Sign into a new output path:

```sh
python3 -I /trusted/wallet_release.py sign \
  --archive /private/download/wallet.tar.gz \
  --private-key /private/offline/publisher.pem \
  --password-file /private/offline/publisher-password \
  --channel invited-rehearsal --sequence 1 \
  --output /private/download/release.json
```

Omit `--password-file` only for an unencrypted, separately protected rehearsal key. This creates `release.json` and `release.json.sig`; existing outputs are refused. The archive itself is unchanged and remains reproducible; ECDSA signatures need not be byte-identical. Signing is not publication, source review or proof that the binary was compiled reproducibly from its declared commit.

Before a tester initializes trust, independently authenticate the publisher key fingerprint, expected profile digest, channel and current minimum acceptable sequence. The public PEM may arrive with the download only if its canonical DER fingerprint matches that independent pin. Initialize once into a new directory, outside wallet data:

```sh
python3 -I /trusted/wallet_release.py init \
  --root /private/wallet-installation \
  --public-key /private/publisher.pub \
  --key-sha256 REVIEWED_PUBLIC_DER_SHA256 \
  --profile-sha256 REVIEWED_EXACT_PROFILE_SHA256 \
  --channel invited-rehearsal --minimum-sequence 1
```

Use actual reviewed hex digests and sequence, not these placeholders. The root must be new. Its private trust/marker/state and version directories must remain operator-owned with safe ancestors. Initialization never reads, resets or moves an existing wallet. A partial initialization is refused rather than silently repaired; retain evidence for operator review. Do not reinitialize to bypass rollback protection or a pending release.

Verify and install without executing downloaded code:

```sh
python3 -I /trusted/wallet_release.py verify \
  --root /private/wallet-installation \
  --archive /private/download/wallet.tar.gz --release /private/download/release.json
python3 -I /trusted/wallet_release.py install \
  --root /private/wallet-installation \
  --archive /private/download/wallet.tar.gz --release /private/download/release.json
python3 -I /trusted/wallet_release.py status --root /private/wallet-installation
```

The tool authenticates the canonical descriptor and separately pinned policy before parsing archive contents. Limits are 64 MiB compressed, 128 MiB file contents plus 2 MiB tar overhead, 1,024 files, 64 MiB per file, 1 MiB manifest, 8 KiB descriptor and 80 bytes of signature. Extraction uses explicit safe paths and regular files, never `extractall`; it preserves the required executable modes and dependency notices. The version's installed files become owner-read-only or owner-read/execute. All directories are private, including intermediate notice folders. Every installed launch rechecks metadata, exact inventory, signature, profile and digests.

Start the authenticated installed wallet through the trusted runner:

```sh
python3 -I /trusted/wallet_release.py run --root /private/wallet-installation -- --verify
python3 -I /trusted/wallet_release.py run --root /private/wallet-installation -- \
  --no-browser --data-dir /private/existing-wallet-data --port 8765 --duration 3600
```

Reuse the original data directory and password. Keep it separate from the installation and every replaceable version. The default remains the existing per-network user application-data directory when `--data-dir` is omitted. The trusted runner takes the installation lock before verification and keeps it throughout wallet execution. Its child wallet inherits the lock if the runner is killed. A live wallet therefore blocks installation; stop the wallet, then retry. The runner uses the current Python interpreter in isolated mode; choose Python 3.10+ for actual wallet execution. Directly invoking an untrusted archive's launcher bypasses this publisher-authentication workflow. The old `start-wallet.command --verify` alone remains a checksum check.

For an update, stop the wallet and repeat `verify/install` with a higher signed sequence and unchanged trust policy. The original accepted sequence survives restart. Older sequences and different content at an already accepted sequence are refused. Reinstalling the identical accepted descriptor is harmless and does not rewrite its version. This is local-state rollback resistance, not a latest-version oracle: an offline new client needs an independently current minimum sequence, and local state rollback/loss or publisher compromise needs separate operator recovery/revocation policy.

The installer records a pending action before writing a version. A crash before activation leaves the previous version active and the original update pending; launching is refused until recovery. A crash after atomic activation leaves the new version selected. Resume by running `install` with the same original archive and signed descriptor. It revalidates everything, reuses a complete published version, or creates a new staging directory. A different update cannot displace an unresolved pending action. Partial staging directories are retained and never automatically deleted. Do not clear `state.json`, markers, trust or signed metadata. Corrupt/missing initialized state and uncertain storage commits fail visibly; restart the process against the original evidence. Storage/backup capacity and manual cleanup policy still need deployment review.

No installer operation reads or migrates encrypted seeds, recovery files, checkpoints, invitations, pending payments, staging records or gas limits. Normal wallet use may update its own data through existing wallet logic. Release recovery does not send/reclaim a payment or resolve an unknown chain outcome. Keep encrypted backups and passwords separate as before.

Run `python3 -B tools/wallet_release_rehearsal.py` for finite local acceptance. It copies the trusted verifier outside the checkout, builds two byte-identical archives from the existing binary without recompilation/downloads, signs with a new local rehearsal key, and runs real installer processes under SIGKILL at four durable stages. A real standalone wallet server exercises inherited locking, and a fresh encrypted wallet's seed/recovery and synthetic pending/staging sentinels remain byte-identical through updates. A seed-only offline restore returns the same address. It starts no validators, sends no RPC or payment requests, and never opens original private service state. See LOCAL-035 evidence.
