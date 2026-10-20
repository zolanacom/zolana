//! Public synthetic fixture keys; use only on isolated, disposable local networks.

use std::{collections::BTreeSet, time::Instant};

use incrementalmerkletree::{Hashable, Level};
use native_payments::{
    staging::{payload_digest, StagedPayload, MAX_CHUNK_BYTES},
    verification::{
        authorization_digest, bundle_version, AuthorizationContext, PaymentVerifier, ValidationView,
    },
    wire, Error,
};
use orchard::{
    builder::{Builder, BundleType},
    bundle::Authorized,
    circuit::ProvingKey,
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    tree::{Anchor, MerkleHashOrchard, MerklePath},
    value::NoteValue,
    Bundle,
};

pub const FIXTURE_GENESIS: [u8; 32] = [0x42; 32];

/// Reuses circuit parameters for real-proof storage stress tests. Public test key!
pub struct DepositProver(ProvingKey);

impl Default for DepositProver {
    fn default() -> Self {
        Self(ProvingKey::build(bundle_version().circuit_version()))
    }
}

impl DepositProver {
    pub fn build(
        &self,
        sponsor: [u8; 32],
        network: [u8; 32],
        expires_at: u64,
        anchor: [u8; 32],
        amount: u64,
    ) -> Result<(Bundle<Authorized, i64>, AuthorizationContext), Box<dyn std::error::Error>> {
        let version = bundle_version();
        let anchor = Option::<Anchor>::from(Anchor::from_bytes(anchor)).ok_or("invalid anchor")?;
        let key =
            Option::<SpendingKey>::from(SpendingKey::from_bytes([7; 32])).ok_or("fixture key")?;
        let mut builder = Builder::new(
            BundleType::DEFAULT,
            version,
            version.default_flags(),
            anchor,
        )?;
        builder.add_output(
            None,
            FullViewingKey::from(&key).address_at(0u32, Scope::External),
            NoteValue::from_raw(amount),
            [0; 512],
        )?;
        let mut rng = rand::rng();
        let (bundle, _) = builder.build::<i64>(&mut rng)?.ok_or("missing deposit")?;
        let context = AuthorizationContext {
            expires_at,
            public_value_balance: -i64::try_from(amount)?,
            sponsor,

            withdrawal_recipient: None,
            shielded_fee: None,
        };
        let digest = authorization_digest(network, &bundle, &context)?;
        Ok((
            bundle
                .create_proof(&self.0, &mut rng)?
                .apply_signatures(&mut rng, digest, &[])?,
            context,
        ))
    }
}

pub struct Fixture {
    pub network: [u8; 32],
    pub current_slot: u64,
    pub funding: Bundle<Authorized, i64>,
    pub funding_context: AuthorizationContext,
    pub verifier: PaymentVerifier,
    pub bundle: Bundle<Authorized, i64>,
    pub context: AuthorizationContext,
    pub anchors: BTreeSet<[u8; 32]>,
    build_ms: u128,
}

pub struct Report {
    pub payload_bytes: usize,
    pub chunks: usize,
    pub build_ms: u128,
    pub verify_ms: u128,
}

impl Fixture {
    pub fn view<'a>(&'a self, spent: &'a BTreeSet<[u8; 32]>) -> ValidationView<'a> {
        ValidationView {
            current_slot: self.current_slot,
            accepted_anchors: &self.anchors,
            spent_nullifiers: spent,
            authorized_public_value_balance: 0,
        }
    }

    pub fn check(&self) -> Result<Report, Error> {
        let bytes = wire::encode(self.network, &self.context, &self.bundle)?;
        let size = bytes.len();
        let mut staged = StagedPayload::new(size, payload_digest(&bytes))?;
        for (i, chunk) in bytes.chunks(MAX_CHUNK_BYTES).enumerate() {
            staged.append(i * MAX_CHUNK_BYTES, chunk)?;
        }
        staged.seal()?;
        let decoded = wire::decode(self.network, &staged.into_payload()?)?;
        let empty = BTreeSet::new();
        let started = Instant::now();
        self.verifier
            .verify(&decoded.bundle, &decoded.context, &self.view(&empty))?;
        Ok(Report {
            payload_bytes: size,
            chunks: size.div_ceil(MAX_CHUNK_BYTES),
            build_ms: self.build_ms,
            verify_ms: started.elapsed().as_millis(),
        })
    }
}

pub fn build_fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    build_fixture_for([0x53; 32])
}

pub fn build_fixture_for(sponsor: [u8; 32]) -> Result<Fixture, Box<dyn std::error::Error>> {
    build_fixture_for_network(sponsor, FIXTURE_GENESIS, 1, 100)
}

/// Constructs real proofs using public test keys for a particular local genesis.
pub fn build_fixture_for_network(
    sponsor: [u8; 32],
    network: [u8; 32],
    current_slot: u64,
    expires_at: u64,
) -> Result<Fixture, Box<dyn std::error::Error>> {
    let started = Instant::now();
    let version = bundle_version();
    let key = ProvingKey::build(version.circuit_version());
    let verifier = PaymentVerifier::new(network, key.verifying_key())?;
    let alice =
        Option::<SpendingKey>::from(SpendingKey::from_bytes([7; 32])).ok_or("fixture key")?;
    let bob = Option::<SpendingKey>::from(SpendingKey::from_bytes([8; 32])).ok_or("fixture key")?;
    let alice_view = FullViewingKey::from(&alice);
    let bob_view = FullViewingKey::from(&bob);
    let alice_address = alice_view.address_at(0u32, Scope::External);
    let bob_address = bob_view.address_at(0u32, Scope::External);
    let mut rng = rand::rng();
    let mut funding = Builder::new(
        BundleType::DEFAULT,
        version,
        version.default_flags(),
        Anchor::empty_tree(),
    )?;
    funding.add_output(None, alice_address, NoteValue::from_raw(100), [0; 512])?;
    let (funding, _) = funding
        .build::<i64>(&mut rng)?
        .ok_or("missing funding fixture")?;
    let funding_context = AuthorizationContext {
        expires_at,
        public_value_balance: -100,
        sponsor,

        withdrawal_recipient: None,
        shielded_fee: None,
    };
    let digest = authorization_digest(network, &funding, &funding_context)?;
    let funding = funding
        .create_proof(&key, &mut rng)?
        .apply_signatures(&mut rng, digest, &[])?;
    let initial_roots = BTreeSet::from([Anchor::empty_tree().to_bytes()]);
    let empty = BTreeSet::new();
    verifier.verify(
        &funding,
        &funding_context,
        &ValidationView {
            current_slot,
            accepted_anchors: &initial_roots,
            spent_nullifiers: &empty,
            authorized_public_value_balance: -100,
        },
    )?;
    let (index, _, note, _, _) = funding
        .decrypt_outputs_with_keys(&[alice_view.to_ivk(Scope::External)])
        .into_iter()
        .find(|(_, _, note, _, _)| note.value().inner() == 100)
        .ok_or("funding note not discovered")?;
    let path = MerklePath::from_parts(
        index as u32,
        std::array::from_fn(|level| {
            if level == 0 {
                MerkleHashOrchard::from_cmx(funding.actions().get(1 - index).unwrap().cmx())
            } else {
                MerkleHashOrchard::empty_root(Level::from(level as u8))
            }
        }),
    );
    let anchor = path.root(note.commitment().into());
    let mut payment = Builder::new(
        BundleType::DEFAULT,
        version,
        version.default_flags(),
        anchor,
    )?;
    payment.add_spend(alice_view.clone(), note, path)?;
    payment.add_output(None, bob_address, NoteValue::from_raw(40), [0; 512])?;
    payment.add_output(None, alice_address, NoteValue::from_raw(60), [0; 512])?;
    let (payment, _) = payment.build::<i64>(&mut rng)?.ok_or("missing payment")?;
    let context = AuthorizationContext {
        public_value_balance: 0,
        ..funding_context
    };
    let digest = authorization_digest(network, &payment, &context)?;
    let bundle = payment.create_proof(&key, &mut rng)?.apply_signatures(
        &mut rng,
        digest,
        &[SpendAuthorizingKey::from(&alice)],
    )?;
    let bob_notes = bundle.decrypt_outputs_with_keys(&[bob_view.to_ivk(Scope::External)]);
    let alice_notes = bundle.decrypt_outputs_with_keys(&[alice_view.to_ivk(Scope::External)]);
    if !bob_notes
        .iter()
        .any(|(_, _, n, _, _)| n.value().inner() == 40)
        || !alice_notes
            .iter()
            .any(|(_, _, n, _, _)| n.value().inner() == 60)
    {
        return Err("payment or change could not be decrypted".into());
    }
    Ok(Fixture {
        network,
        current_slot,
        funding,
        funding_context,
        verifier,
        bundle,
        context,
        anchors: BTreeSet::from([anchor.to_bytes()]),
        build_ms: started.elapsed().as_millis(),
    })
}

/// Synthetic exit fixture: Bob authorizes a public withdrawal to the bound sponsor.
pub fn withdrawal_fixture(
    fixture: &Fixture,
) -> Result<(Bundle<Authorized, i64>, AuthorizationContext), Box<dyn std::error::Error>> {
    let version = bundle_version();
    let bob = Option::<SpendingKey>::from(SpendingKey::from_bytes([8; 32])).ok_or("fixture key")?;
    let view = FullViewingKey::from(&bob);
    let (index, _, note, _, _) = fixture
        .bundle
        .decrypt_outputs_with_keys(&[view.to_ivk(Scope::External)])
        .into_iter()
        .find(|(_, _, n, _, _)| n.value().inner() == 40)
        .ok_or("fixture payment")?;
    let funding_root = MerkleHashOrchard::combine(
        Level::from(0),
        &MerkleHashOrchard::from_cmx(fixture.funding.actions().get(0).unwrap().cmx()),
        &MerkleHashOrchard::from_cmx(fixture.funding.actions().get(1).unwrap().cmx()),
    );
    let path = MerklePath::from_parts(
        (2 + index) as u32,
        std::array::from_fn(|level| match level {
            0 => {
                MerkleHashOrchard::from_cmx(fixture.bundle.actions().get(1 - index).unwrap().cmx())
            }
            1 => funding_root,
            _ => MerkleHashOrchard::empty_root(Level::from(level as u8)),
        }),
    );
    let anchor = path.root(note.commitment().into());
    let mut builder = Builder::new(
        BundleType::DEFAULT,
        version,
        version.default_flags(),
        anchor,
    )?;
    builder.add_spend(view, note, path)?;
    let mut rng = rand::rng();
    let (bundle, _) = builder
        .build::<i64>(&mut rng)?
        .ok_or("withdrawal fixture")?;
    let context = AuthorizationContext {
        public_value_balance: 40,
        ..fixture.context
    };
    let digest = authorization_digest(fixture.network, &bundle, &context)?;
    let key = ProvingKey::build(version.circuit_version());
    Ok((
        bundle.create_proof(&key, &mut rng)?.apply_signatures(
            &mut rng,
            digest,
            &[SpendAuthorizingKey::from(&bob)],
        )?,
        context,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::{bundle::Authorized, primitives::redpallas, Proof};

    #[test]
    fn real_private_payment_rejects_mutation_replay_and_wrong_context() {
        let fixture = build_fixture().expect("real payment fixture");
        let report = fixture.check().expect("staged cryptographic round trip");
        println!(
            "proof fixture: build_ms={} verify_ms={} payload_bytes={} chunks={}",
            report.build_ms, report.verify_ms, report.payload_bytes, report.chunks
        );
        let empty = BTreeSet::new();
        let effects = fixture
            .verifier
            .verify(&fixture.bundle, &fixture.context, &fixture.view(&empty))
            .unwrap();

        let spent = BTreeSet::from([effects.nullifiers[0]]);
        assert_eq!(
            fixture
                .verifier
                .verify(&fixture.bundle, &fixture.context, &fixture.view(&spent)),
            Err(Error::SpentNullifier)
        );
        let context = AuthorizationContext {
            sponsor: [9; 32],
            ..fixture.context
        };
        assert_eq!(
            fixture
                .verifier
                .verify(&fixture.bundle, &context, &fixture.view(&empty)),
            Err(Error::InvalidSpendAuthorization)
        );
        let context = AuthorizationContext {
            expires_at: 99,
            ..fixture.context
        };
        assert_eq!(
            fixture
                .verifier
                .verify(&fixture.bundle, &context, &fixture.view(&empty)),
            Err(Error::InvalidSpendAuthorization)
        );
        let context = AuthorizationContext {
            public_value_balance: 1,
            ..fixture.context
        };
        assert_eq!(
            fixture
                .verifier
                .verify(&fixture.bundle, &context, &fixture.view(&empty)),
            Err(Error::WrongValueBalance)
        );
        let mut view = fixture.view(&empty);
        view.current_slot = 101;
        assert_eq!(
            fixture
                .verifier
                .verify(&fixture.bundle, &fixture.context, &view),
            Err(Error::Expired)
        );
        let mut view = fixture.view(&empty);
        view.accepted_anchors = &empty;
        assert_eq!(
            fixture
                .verifier
                .verify(&fixture.bundle, &fixture.context, &view),
            Err(Error::UnknownAnchor)
        );

        let unsupported = Bundle::try_from_parts(
            fixture.bundle.actions().clone(),
            *fixture.bundle.flags(),
            *fixture.bundle.value_balance(),
            *fixture.bundle.anchor(),
            fixture.bundle.authorization().clone(),
            orchard::bundle::BundleVersion::orchard_insecure_v1(),
        )
        .unwrap();
        assert_eq!(
            fixture
                .verifier
                .verify(&unsupported, &fixture.context, &fixture.view(&empty)),
            Err(Error::UnsupportedVersion)
        );
        let context = AuthorizationContext {
            expires_at: 10_000,
            ..fixture.context
        };
        assert_eq!(
            fixture
                .verifier
                .verify(&fixture.bundle, &context, &fixture.view(&empty)),
            Err(Error::InvalidContext)
        );

        let corrupted = fixture.bundle.clone().map_authorization(
            &mut (),
            |_, _, sig| sig,
            |_, auth| {
                let mut proof = auth.proof().as_ref().to_vec();
                proof[0] ^= 1;
                Authorized::from_parts(Proof::new(proof), auth.binding_signature().clone())
            },
        );
        assert_eq!(
            fixture
                .verifier
                .verify(&corrupted, &fixture.context, &fixture.view(&empty)),
            Err(Error::InvalidProof)
        );
        let corrupted = fixture.bundle.clone().map_authorization(
            &mut (),
            |_, _, sig| sig,
            |_, auth| {
                Authorized::from_parts(auth.proof().clone(), redpallas::Signature::from([0; 64]))
            },
        );
        assert_eq!(
            fixture
                .verifier
                .verify(&corrupted, &fixture.context, &fixture.view(&empty)),
            Err(Error::InvalidBindingSignature)
        );
        let corrupted = fixture.bundle.clone().map_authorization(
            &mut (),
            |_, _, _| redpallas::Signature::from([0; 64]),
            |_, auth| auth,
        );
        assert_eq!(
            fixture
                .verifier
                .verify(&corrupted, &fixture.context, &fixture.view(&empty)),
            Err(Error::InvalidSpendAuthorization)
        );

        let bytes = wire::encode(FIXTURE_GENESIS, &fixture.context, &fixture.bundle).unwrap();
        assert!(matches!(
            wire::decode([9; 32], &bytes),
            Err(Error::WrongNetwork)
        ));
        for length in 0..bytes.len() {
            assert!(wire::decode(FIXTURE_GENESIS, &bytes[..length]).is_err());
        }
        let mut altered = bytes.clone();
        altered.push(0);
        assert!(matches!(
            wire::decode(FIXTURE_GENESIS, &altered),
            Err(Error::InvalidLength)
        ));
        let mut altered = bytes.clone();
        altered[121] = 255;
        assert!(matches!(
            wire::decode(FIXTURE_GENESIS, &altered),
            Err(Error::InvalidShape)
        ));
        let mut altered = bytes.clone();
        altered[120] = 0;
        assert!(matches!(
            wire::decode(FIXTURE_GENESIS, &altered),
            Err(Error::InvalidShape)
        ));
        let mut altered = bytes.clone();
        let first_nullifier = altered[122..154].to_vec();
        altered[122 + 884..154 + 884].copy_from_slice(&first_nullifier);
        let decoded = wire::decode(FIXTURE_GENESIS, &altered).unwrap();
        assert_eq!(
            fixture
                .verifier
                .verify(&decoded.bundle, &decoded.context, &fixture.view(&empty)),
            Err(Error::DuplicateNullifier)
        );
        let mut altered = bytes.clone();
        altered[8..40].copy_from_slice(&[9; 32]);
        let decoded = wire::decode([9; 32], &altered).unwrap();
        let other = PaymentVerifier::new(
            [9; 32],
            orchard::circuit::VerifyingKey::build(bundle_version().circuit_version()),
        )
        .unwrap();
        assert_eq!(
            other.verify(&decoded.bundle, &decoded.context, &fixture.view(&empty)),
            Err(Error::InvalidSpendAuthorization)
        );
        let mut altered = bytes;
        // First action's encrypted ciphertext, retaining valid curve encodings.
        altered[122 + 128] ^= 1;
        let decoded = wire::decode(FIXTURE_GENESIS, &altered).unwrap();
        assert_eq!(
            fixture
                .verifier
                .verify(&decoded.bundle, &decoded.context, &fixture.view(&empty)),
            Err(Error::InvalidSpendAuthorization)
        );
    }
}
