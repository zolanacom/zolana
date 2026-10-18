# Third-party source

`node/agave/` contains the upstream Agave v3.0.14 source snapshot from <https://github.com/anza-xyz/agave>, commit `f516a8927c76c07f0ebc54ca7a4ce8b2046eee86`. It retains its Apache-2.0 license and file-specific notices. Dependencies retain their own licenses and authorship.

The independent payment module is new project code. Its use of third-party cryptographic libraries does not imply endorsement or inherited security of the integration.

Local modifications to the Agave snapshot register a gated native-payment built-in pin matching syscall APIs, update the toolchain and make explicit lifetime annotations and narrow warning compatibility fixes for Rust 1.92. The pristine upstream source tree is recorded as `a4c75a1781d4ca56e7325a39d0614e1faa26030d`. Existing upstream licenses and notices remain in place.

Local validator build support also selects the upstream networking patches and release-compatible SDK types through the root lockfile, uses a Cargo-packaged Protocol Buffers compiler, and provides an optional platform-allocator build for paths unsupported by jemalloc. The scheduler benchmark retains its allocator as a development dependency. Compiler-compatibility annotations in ledger, gossip and core code do not change their algorithms.

The feature-set and SVM feature mapping also include a separate gate for recipient-bound native withdrawals. Existing payment activation and historical payloads remain supported; the new gate is enabled explicitly in fresh local genesis. Payment authorization and account movement remain in the independent protocol/adapter modules.

The RPC HTTP sender also returns an ordinary error for unfollowed 3xx responses instead of assuming every non-success status is a reqwest 4xx/5xx error and panicking. The wallet disables redirects explicitly. This does not alter validator consensus.
