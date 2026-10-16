# 0002: First validation boundary

The payment workspace pins Orchard 0.16.0 and uses `BundleVersion::orchard_v2()` with its patched circuit. Historical insecure v1 is explicitly rejected. The standalone workspace uses the installed Rust 1.92 toolchain; the vendored node retains its upstream toolchain until native integration is tested.

Authorization commits to the genesis identifier, protocol version, complete Orchard effects commitment, expiry, public value movement and sponsor. Verification checks two actions, exact proof shape, accepted root, spent and duplicate nullifiers, every spend signature, the binding signature and the proof. Individual verification avoids an external verifier or a randomized batch-acceptance decision.

The experimental wire format is fixed-shape and rejects unknown versions, noncanonical field/point encodings, incorrect length, padding and unsupported action counts before unbounded allocation. It transports only ciphertext, public commitments, authorization and context. It is not a released protocol specification.

Staging is bounded to 16 KiB, accepts sequential chunks of at most 768 bytes, verifies a content digest and becomes immutable when sealed. The measured two-action fixture is 9,222 bytes, requiring 13 such chunks. Actual signed outer transaction sizing, sponsor authority, rent, expiry and persisted staging ownership remain node-adapter work.

The validator is read-only. Its `ValidationView` must come from authenticated node state. In particular, a caller-provided negative value balance is not proof that public funds were debited. The offline fixture uses synthetic funding. Production issuance, native reserve accounting, atomic ledger updates, fork recovery and real fee charging are not implemented here.

Dependency release and circuit versions are pinned, but no complete dependency advisory audit or independent cryptographic review has been completed. Those checks remain required before external use.
