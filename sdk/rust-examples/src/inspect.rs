//! Read a payment from its bytes and report what those bytes prove.
//!
//! [`inspect`] decodes a payment (or the inline envelope around one) with
//! `native_payments::wire`, then checks its signatures and its proof with
//! `PaymentVerifier`. It has no chain to ask, so three things a validator
//! takes from authenticated state are taken from the payment itself: the slot
//! (its own expiry), the accepted anchors (its own anchor) and the public
//! value it is allowed to move (its own value balance). No nullifier counts as
//! spent. A payment that passes here is internally valid; whether a chain
//! would accept it is a separate question that these bytes cannot answer.
use crate::hex;
use native_payments::{
    envelope,
    native_accounts::nullifier_address,
    staging::payload_digest,
    verification::{PaymentVerifier, ValidationView, MAX_EXPIRY_WINDOW},
    wire, Error,
};
use orchard::circuit::VerifyingKey;
use std::{collections::BTreeSet, fmt::Write as _, sync::Arc};

/// Tag of the inline envelope (`native_payments::envelope`).
pub const ENVELOPE_TAG: &[u8; 8] = b"ZOLNPAY1";

/// Builds the public verifying key of the payment circuit. Takes a moment;
/// build it once per process and share it.
pub fn verifying_key() -> Arc<VerifyingKey> {
    let version = native_payments::verification::bundle_version();
    Arc::new(VerifyingKey::build(version.circuit_version()))
}

/// What the tag and the public value balance say a payment is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `NPAY0001`, negative balance: public coins enter the pool.
    Deposit,
    /// `NPAY0001`, zero balance: no public value moves.
    PrivateSend,
    /// `NPAY0001`, positive balance: value leaves the pool to the sponsor.
    SponsorWithdrawal,
    /// `NPAY0002`: value leaves the pool to the recipient named in the bytes.
    RecipientWithdrawal,
    /// `NPAY0003`: only the fee leaves the pool, to the sponsor.
    ShieldedFeePayment,
}

impl Kind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deposit => "deposit",
            Self::PrivateSend => "private-send",
            Self::SponsorWithdrawal => "sponsor-withdrawal",
            Self::RecipientWithdrawal => "recipient-withdrawal",
            Self::ShieldedFeePayment => "shielded-fee-payment",
        }
    }
}

/// The public values of one action. Every action carries both, whether or not
/// it spends or creates a real note; the bytes do not say which.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActionSummary {
    pub nullifier: [u8; 32],
    pub commitment: [u8; 32],
}

#[derive(Debug, PartialEq, Eq)]
pub struct Inspection {
    /// True when the input was an inline envelope around the payment.
    pub enveloped: bool,
    /// Length of the input, and of the payment inside it.
    pub bytes: usize,
    pub payment_bytes: usize,
    pub tag: String,
    pub kind: Kind,
    pub network: [u8; 32],
    /// `staging::payload_digest` of the payment bytes.
    pub payment_id: [u8; 32],
    pub expires_at: u64,
    pub public_value_balance: i64,
    pub shielded_fee: Option<u64>,
    pub sponsor: [u8; 32],
    pub withdrawal_recipient: Option<[u8; 32]>,
    pub anchor: [u8; 32],
    pub actions: Vec<ActionSummary>,
    /// `Ok` when the spend authorization signatures, the binding signature and
    /// the proof are valid for these bytes; otherwise the verifier's refusal.
    pub verification: Result<(), Error>,
}

/// Turns the text or bytes a developer has into payment bytes: the raw bytes
/// themselves, their hex, or their base64 (the form the RPC methods carry).
pub fn parse_input(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.starts_with(b"NPAY000") || input.starts_with(ENVELOPE_TAG) {
        return Ok(input.to_vec());
    }
    let text = std::str::from_utf8(input).map_err(|_| "input is neither payment bytes nor text")?;
    let text: String = text.split_ascii_whitespace().collect();
    if text.is_empty() {
        return Err("input is empty".into());
    }
    if text.len().is_multiple_of(2) && text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok((0..text.len() / 2)
            .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("checked"))
            .collect());
    }
    base64(&text).ok_or_else(|| "input is neither hex nor base64".into())
}

/// Standard-alphabet base64 with optional padding.
fn base64(text: &str) -> Option<Vec<u8>> {
    let digits = text.trim_end_matches('=');
    if text.len() - digits.len() > 2 || digits.len() % 4 == 1 {
        return None;
    }
    let mut bytes = Vec::with_capacity(digits.len() * 3 / 4);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for digit in digits.bytes() {
        let value = match digit {
            b'A'..=b'Z' => digit - b'A',
            b'a'..=b'z' => digit - b'a' + 26,
            b'0'..=b'9' => digit - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    (buffer == 0).then_some(bytes)
}

/// Decodes and verifies `input`. The network is read from the bytes; pass
/// `expected_network` to refuse a payment made for any other network.
pub fn inspect(
    input: &[u8],
    expected_network: Option<[u8; 32]>,
    key: &Arc<VerifyingKey>,
) -> Result<Inspection, Error> {
    let enveloped = input.starts_with(ENVELOPE_TAG);
    // The network field follows the tag (and, in an envelope, the version and
    // the framing domain). Decoding checks it against the network it is given.
    let offset = if enveloped { 8 + 2 + 16 } else { 8 };
    let network: [u8; 32] = input
        .get(offset..offset + 32)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Error::InvalidLength)?;
    if expected_network.is_some_and(|expected| expected != network) {
        return Err(Error::WrongNetwork);
    }
    let (payment, payload) = if enveloped {
        // The envelope repeats the signed expiry at a fixed offset. Using it
        // as the current slot checks the framing without consulting a chain.
        let expiry = input
            .get(offset + 32..offset + 40)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_le_bytes)
            .ok_or(Error::InvalidLength)?;
        let opened = envelope::decode(network, expiry, input)?;
        let payload = &input[envelope::ENVELOPE_HEADER_BYTES..];
        (opened.payment, payload)
    } else {
        (wire::decode(network, input)?, input)
    };
    let (context, bundle) = (&payment.context, &payment.bundle);
    let tag = String::from_utf8_lossy(&payload[..8]).into_owned();
    let kind = if context.shielded_fee.is_some() {
        Kind::ShieldedFeePayment
    } else if context.withdrawal_recipient.is_some() {
        Kind::RecipientWithdrawal
    } else {
        match context.public_value_balance {
            i64::MIN..=-1 => Kind::Deposit,
            0 => Kind::PrivateSend,
            1.. => Kind::SponsorWithdrawal,
        }
    };
    let anchor = bundle.anchor().to_bytes();
    let (anchors, spent) = (BTreeSet::from([anchor]), BTreeSet::new());
    let view = ValidationView {
        current_slot: context.expires_at,
        accepted_anchors: &anchors,
        spent_nullifiers: &spent,
        authorized_public_value_balance: context.public_value_balance,
    };
    let verification = PaymentVerifier::with_shared_key(network, Arc::clone(key))?
        .verify(bundle, context, &view)
        .map(|_| ());
    Ok(Inspection {
        enveloped,
        bytes: input.len(),
        payment_bytes: payload.len(),
        tag,
        kind,
        network,
        payment_id: payload_digest(payload),
        expires_at: context.expires_at,
        public_value_balance: context.public_value_balance,
        shielded_fee: context.shielded_fee,
        sponsor: context.sponsor,
        withdrawal_recipient: context.withdrawal_recipient,
        anchor,
        actions: bundle
            .actions()
            .iter()
            .map(|action| ActionSummary {
                nullifier: action.nullifier().to_bytes(),
                commitment: action.cmx().to_bytes(),
            })
            .collect(),
        verification,
    })
}

fn base58(bytes: &[u8; 32]) -> String {
    bs58::encode(bytes).into_string()
}

impl Inspection {
    /// One sentence on the public value this payment moves, and where.
    pub fn public_value(&self) -> String {
        let amount = self.public_value_balance.unsigned_abs();
        match self.kind {
            Kind::Deposit => format!("{amount} units enter the pool, debited from the sponsor"),
            Kind::PrivateSend => "none moves".to_owned(),
            Kind::SponsorWithdrawal => format!("{amount} units leave the pool to the sponsor"),
            Kind::RecipientWithdrawal => {
                format!("{amount} units leave the pool to the withdrawal recipient")
            }
            Kind::ShieldedFeePayment => {
                format!("{amount} units leave the pool to the sponsor as the fee")
            }
        }
    }

    /// The report for a person. The same input always gives the same text.
    pub fn text(&self) -> String {
        let mut out = String::new();
        let mut line = |name: &str, value: &dyn std::fmt::Display| {
            let line = format!("{name:<20} {value}");
            writeln!(out, "{}", line.trim_end()).expect("writing to a string");
        };
        if self.enveloped {
            let (bytes, inner, tag) = (self.bytes, self.payment_bytes, &self.tag);
            line(
                "input",
                &format!("{bytes} bytes, an inline envelope around a {inner}-byte {tag} payment"),
            );
        } else {
            line("input", &format!("{} bytes, tag {}", self.bytes, self.tag));
        }
        line("kind", &self.kind.as_str());
        line("network", &hex(&self.network));
        line("payment id", &hex(&self.payment_id));
        line("expiry slot", &self.expires_at);
        line("public value", &self.public_value());
        if let Some(fee) = self.shielded_fee {
            line("shielded fee", &fee);
        }
        line("sponsor", &base58(&self.sponsor));
        if let Some(recipient) = &self.withdrawal_recipient {
            line("recipient", &base58(recipient));
        }
        line("anchor", &hex(&self.anchor));
        for (index, action) in self.actions.iter().enumerate() {
            line(&format!("action {index}"), &"");
            line("  nullifier", &hex(&action.nullifier));
            // The account that exists on a chain once this nullifier is spent.
            line(
                "  nullifier account",
                &base58(&nullifier_address(&action.nullifier)),
            );
            line("  commitment", &hex(&action.commitment));
        }
        match self.verification {
            Ok(()) => line(
                "verified",
                &"the spend authorization signatures, the binding signature and the proof",
            ),
            Err(error) => line(
                "NOT VERIFIED",
                &format!("{error}: treat every value above as unauthenticated"),
            ),
        }
        line(
            "not revealed",
            &"the shielded addresses, the value of each note and the memos",
        );
        line(
            "",
            &"which actions spend or create a real note, and which are padding",
        );
        line("not checked", &"that any chain accepts this anchor");
        line("", &"that the nullifiers are unspent");
        line(
            "",
            &format!(
                "the current slot: the verifier accepts this payment from slot {} through slot {}",
                self.expires_at.saturating_sub(MAX_EXPIRY_WINDOW),
                self.expires_at
            ),
        );
        line("", &"that the public accounts exist and can pay or be paid");
        line("", &"that the payment was ever submitted or finalized");
        out
    }

    /// The same report as one JSON object. 64-bit integers are decimal
    /// strings, 32-byte values are hex, and public accounts are base58.
    pub fn json(&self) -> String {
        let text = |value: String| format!("\"{value}\"");
        let optional = |value: Option<String>| value.map_or("null".to_owned(), text);
        let actions: Vec<String> = self
            .actions
            .iter()
            .map(|action| {
                format!(
                    "{{\"nullifier\":\"{}\",\"nullifier_account\":\"{}\",\"commitment\":\"{}\"}}",
                    hex(&action.nullifier),
                    base58(&nullifier_address(&action.nullifier)),
                    hex(&action.commitment)
                )
            })
            .collect();
        let fields = [
            (
                "container",
                text(
                    if self.enveloped {
                        "inline-envelope"
                    } else {
                        "payment"
                    }
                    .into(),
                ),
            ),
            ("bytes", self.bytes.to_string()),
            ("payment_bytes", self.payment_bytes.to_string()),
            ("tag", text(self.tag.clone())),
            ("kind", text(self.kind.as_str().into())),
            ("network", text(hex(&self.network))),
            ("payment_id", text(hex(&self.payment_id))),
            ("expiry_slot", text(self.expires_at.to_string())),
            (
                "public_value_balance",
                text(self.public_value_balance.to_string()),
            ),
            (
                "shielded_fee",
                optional(self.shielded_fee.map(|fee| fee.to_string())),
            ),
            ("sponsor", text(base58(&self.sponsor))),
            (
                "withdrawal_recipient",
                optional(self.withdrawal_recipient.as_ref().map(base58)),
            ),
            ("anchor", text(hex(&self.anchor))),
            ("actions", format!("[{}]", actions.join(","))),
            (
                "verification",
                text(
                    self.verification
                        .map_or_else(|error| error.to_string(), |()| "ok".into()),
                ),
            ),
        ];
        let body: Vec<String> = fields
            .iter()
            .map(|(name, value)| format!("\"{name}\":{value}"))
            .collect();
        format!("{{{}}}", body.join(","))
    }
}
