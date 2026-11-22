//! Shared pieces of the decoder fuzz targets and the pool property tests: a
//! value-stable generator, the run budget, byte mutators and a reducer that
//! shrinks a failing input towards the valid encoding it was derived from.
//!
//! Nothing here is coverage guided. The targets take plain byte slices, so a
//! coverage-guided engine can drive the same checks later without changes.
#![allow(dead_code)]

pub mod reference;

use std::{
    any::Any,
    io::Write,
    panic::{catch_unwind, AssertUnwindSafe},
    time::{Duration, Instant},
};

/// Network domain used by every fixture.
pub const NETWORK: [u8; 32] = [42; 32];

const DEFAULT_SEED: u64 = 0x6e70_6179_6675_7a7a;
const REDUCTION_ATTEMPTS: usize = 20_000;

/// SplitMix64. Small, and its output never changes between releases of any
/// dependency, so a reported seed reproduces the same cases everywhere.
#[derive(Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    /// Uniform enough for test generation; the bound must be positive.
    pub fn below(&mut self, bound: u64) -> u64 {
        assert!(bound > 0);
        self.next() % bound
    }

    pub fn index(&mut self, length: usize) -> usize {
        self.below(length as u64) as usize
    }

    pub fn chance(&mut self, numerator: u64, denominator: u64) -> bool {
        self.below(denominator) < numerator
    }

    pub fn fill(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(8) {
            let word = self.next().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
    }

    pub fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut bytes = [0; N];
        self.fill(&mut bytes);
        bytes
    }

    pub fn bytes(&mut self, length: usize) -> Vec<u8> {
        let mut bytes = vec![0; length];
        self.fill(&mut bytes);
        bytes
    }

    pub fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.index(items.len())]
    }

    /// A canonical encoding of a Pallas base field element: any value below
    /// 2^254 is below the modulus.
    pub fn field_element(&mut self) -> [u8; 32] {
        let mut bytes: [u8; 32] = self.array();
        bytes[31] &= 0x3f;
        if bytes == [0; 32] {
            bytes[0] = 1;
        }
        bytes
    }
}

/// How long one target runs. `PROTOCOL_FUZZ_SCALE` multiplies the built-in case
/// count, `PROTOCOL_FUZZ_SECONDS` replaces it with a time limit for each target
/// and `PROTOCOL_FUZZ_SEED` selects a different sequence of cases.
pub struct Budget {
    target: &'static str,
    seed: u64,
    cases: u64,
    limit: Option<Duration>,
    started: Instant,
    run: u64,
}

impl Budget {
    pub fn new(target: &'static str, base_cases: u64) -> Self {
        let scale = setting("PROTOCOL_FUZZ_SCALE").unwrap_or(1).max(1);
        Self {
            target,
            seed: setting("PROTOCOL_FUZZ_SEED").unwrap_or(DEFAULT_SEED),
            cases: base_cases.saturating_mul(scale),
            limit: setting("PROTOCOL_FUZZ_SECONDS").map(Duration::from_secs),
            started: Instant::now(),
            run: 0,
        }
    }

    /// The generator of the next case, or `None` once the budget is spent.
    pub fn next_case(&mut self) -> Option<Rng> {
        let spent = match self.limit {
            Some(limit) => self.started.elapsed() >= limit,
            None => self.run >= self.cases,
        };
        if spent {
            return None;
        }
        let mut name = 0xcbf2_9ce4_8422_2325u64;
        for byte in self.target.bytes() {
            name = (name ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3);
        }
        let mut stream = Rng::new(self.seed ^ name);
        let case = Rng::new(stream.next() ^ self.run.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        self.run += 1;
        Some(case)
    }

    pub fn cases_run(&self) -> u64 {
        self.run
    }

    /// One line per target, visible with `--nocapture`.
    pub fn finish(&self, outcome: impl std::fmt::Display) {
        report(format!(
            "fuzz {}: {} cases, {}, {:.1} s, seed {}",
            self.target,
            self.run,
            outcome,
            self.started.elapsed().as_secs_f64(),
            self.seed
        ));
    }

    /// The usual outcome of a decoder target.
    pub fn finish_decoder(&self, accepted: u64) {
        self.finish(format_args!(
            "{accepted} accepted, {} refused",
            self.run - accepted
        ));
    }
}

/// Names the case and the seed when a target fails, whatever printed the
/// failure, so that the run can be repeated.
impl Drop for Budget {
    fn drop(&mut self) {
        if std::thread::panicking() {
            report(format!(
                "fuzz {}: failed in case {} of seed {} (PROTOCOL_FUZZ_SEED={} repeats the run)",
                self.target,
                self.run.saturating_sub(1),
                self.seed,
                self.seed
            ));
        }
    }
}

/// Writes one whole line at once, so that targets running on other threads
/// cannot split it.
pub fn report(mut line: String) {
    line.push('\n');
    let _ = std::io::stderr().write_all(line.as_bytes());
}

fn setting(name: &str) -> Option<u64> {
    let text = std::env::var(name).ok()?;
    Some(
        text.parse()
            .unwrap_or_else(|_| panic!("{name} must be an unsigned integer, found {text:?}")),
    )
}

/// A contiguous run of bytes that the encoding treats as one value.
#[derive(Clone, Copy, Debug)]
pub struct Field {
    pub offset: usize,
    pub len: usize,
}

/// Fields laid end to end from `start`, one per length.
pub fn layout(start: usize, lengths: &[usize]) -> Vec<Field> {
    let mut offset = start;
    lengths
        .iter()
        .map(|len| {
            let field = Field { offset, len: *len };
            offset += len;
            field
        })
        .collect()
}

pub const INTERESTING: &[u64] = &[
    0,
    1,
    2,
    3,
    4,
    63,
    64,
    65,
    255,
    256,
    511,
    512,
    513,
    1_023,
    1_024,
    1_025,
    16_383,
    16_384,
    16_385,
    u16::MAX as u64,
    (1 << 32) - 4,
    (1 << 32) - 3,
    (1 << 32) - 2,
    (1 << 32) - 1,
    1 << 32,
    i64::MAX as u64 - 1,
    i64::MAX as u64,
    1 << 63,
    u64::MAX - 1,
    u64::MAX,
];

fn read_integer(bytes: &[u8]) -> u64 {
    let mut word = [0; 8];
    word[..bytes.len()].copy_from_slice(bytes);
    u64::from_le_bytes(word)
}

fn write_integer(bytes: &mut [u8], value: u64) {
    let length = bytes.len();
    bytes.copy_from_slice(&value.to_le_bytes()[..length]);
}

/// One mutation. Most of them respect field boundaries so that a mutated
/// encoding stays close enough to a valid one to reach the deeper checks.
/// `donor` is another valid encoding to borrow bytes from.
pub fn mutate(rng: &mut Rng, bytes: &mut Vec<u8>, fields: &[Field], donor: &[u8]) {
    if bytes.is_empty() {
        *bytes = rng.bytes(1);
        return;
    }
    let fields: Vec<Field> = fields
        .iter()
        .copied()
        .filter(|field| field.len > 0 && field.offset + field.len <= bytes.len())
        .collect();
    let kind = rng.below(13);
    if fields.is_empty() || kind >= 9 {
        match kind % 4 {
            0 => {
                let position = rng.index(bytes.len());
                bytes[position] ^= 1 << rng.below(8);
            }
            1 => {
                let position = rng.index(bytes.len());
                bytes[position] = rng.pick(&[0, 1, 2, 0x3f, 0x40, 0x7f, 0x80, 0xfe, 0xff]);
            }
            2 => {
                let cut = match rng.below(3) {
                    0 if !fields.is_empty() => rng.pick(&fields).offset,
                    1 => bytes.len() - 1,
                    _ => rng.index(bytes.len()),
                };
                bytes.truncate(cut);
            }
            _ => {
                let most = if rng.chance(1, 4) { 600 } else { 4 };
                let extra = 1 + rng.index(most);
                if rng.chance(1, 2) {
                    bytes.resize(bytes.len() + extra, 0);
                } else {
                    let tail = rng.bytes(extra);
                    bytes.extend_from_slice(&tail);
                }
            }
        }
        return;
    }
    let field = rng.pick(&fields);
    let range = field.offset..field.offset + field.len;
    match kind {
        0 if field.len <= 8 => {
            let delta = 1 + rng.below(4);
            let value = read_integer(&bytes[range.clone()]);
            let value = if rng.chance(1, 2) {
                value.wrapping_add(delta)
            } else {
                value.wrapping_sub(delta)
            };
            write_integer(&mut bytes[range], value);
        }
        1 if field.len <= 8 => {
            let value = rng.pick(INTERESTING);
            write_integer(&mut bytes[range], value);
        }
        2 => bytes[range].fill(0),
        3 => bytes[range].fill(0xff),
        4 => rng.fill(&mut bytes[range]),
        5 if field.len == 32 => {
            let element = rng.field_element();
            bytes[range].copy_from_slice(&element);
        }
        6 => {
            let same: Vec<Field> = fields
                .iter()
                .copied()
                .filter(|other| other.len == field.len && other.offset != field.offset)
                .collect();
            if !same.is_empty() {
                let other = rng.pick(&same);
                bytes.copy_within(other.offset..other.offset + other.len, field.offset);
            }
        }
        7 if donor.len() >= field.offset + field.len => {
            bytes[range.clone()].copy_from_slice(&donor[range]);
        }
        _ => {
            let position = field.offset + rng.index(field.len);
            bytes[position] ^= 1 << rng.below(8);
        }
    }
}

/// One to three stacked mutations of `base`.
pub fn mutated(rng: &mut Rng, base: &[u8], fields: &[Field], donor: &[u8]) -> Vec<u8> {
    let mut bytes = base.to_vec();
    for _ in 0..1 + rng.below(3) {
        mutate(rng, &mut bytes, fields, donor);
    }
    bytes
}

fn panic_text(payload: &(dyn Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "a panic without a message".to_string()
    }
}

/// The verdict of a check on one input. A panic in the code under test is a
/// failure like any other, so that the input which caused it can be reported.
pub fn verdict(check: &dyn Fn(&[u8]) -> Result<(), String>, input: &[u8]) -> Result<(), String> {
    match catch_unwind(AssertUnwindSafe(|| check(input))) {
        Ok(result) => result,
        Err(payload) => Err(format!("panicked: {}", panic_text(payload.as_ref()))),
    }
}

/// Puts bytes of `failing` back to their value in `base` for as long as the
/// result still fails, so the report shows only the bytes that matter.
pub fn reduce(base: &[u8], failing: &[u8], fails: &dyn Fn(&[u8]) -> bool) -> Vec<u8> {
    let mut current = failing.to_vec();
    let mut attempts = 0;
    if base.len() != current.len() {
        // Prefer the base length when the failure does not depend on it.
        let mut candidate = base.to_vec();
        let shared = base.len().min(current.len());
        candidate[..shared].copy_from_slice(&current[..shared]);
        attempts += 1;
        if fails(&candidate) {
            current = candidate;
        }
    }
    let shared = base.len().min(current.len());
    let mut different: Vec<usize> = (0..shared)
        .filter(|position| base[*position] != current[*position])
        .collect();
    let mut step = different.len();
    while step > 0 && attempts < REDUCTION_ATTEMPTS {
        let mut start = 0;
        while start < different.len() && attempts < REDUCTION_ATTEMPTS {
            let end = (start + step).min(different.len());
            let mut candidate = current.clone();
            for position in &different[start..end] {
                candidate[*position] = base[*position];
            }
            attempts += 1;
            if fails(&candidate) {
                current = candidate;
                different.drain(start..end);
            } else {
                start = end;
            }
        }
        if step == 1 {
            break;
        }
        step = step.div_ceil(2);
    }
    current
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The non-zero runs of an encoding as `offset:hex`, for inputs that are
/// mostly padding.
pub fn sparse(bytes: &[u8]) -> String {
    let mut runs = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == 0 {
            at += 1;
            continue;
        }
        // A run ends where four zero bytes in a row begin.
        let end = (at..bytes.len())
            .find(|position| bytes[*position..].iter().take(4).all(|byte| *byte == 0))
            .unwrap_or(bytes.len());
        runs.push(format!("{at}:{}", hex(&bytes[at..end])));
        at = end;
    }
    format!("{} bytes, zero except [{}]", bytes.len(), runs.join(" "))
}

pub fn unhex(text: &str) -> Vec<u8> {
    let text: Vec<u8> = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    assert!(text.len().is_multiple_of(2), "odd number of hex digits");
    text.chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn difference(base: &[u8], input: &[u8]) -> String {
    let shared = base.len().min(input.len());
    let changed: Vec<String> = (0..shared)
        .filter(|position| base[*position] != input[*position])
        .take(48)
        .map(|position| format!("{position}:{:02x}->{:02x}", base[position], input[position]))
        .collect();
    format!(
        "against the valid encoding it came from ({} bytes): length {}, changed bytes [{}]",
        base.len(),
        input.len(),
        changed.join(" ")
    )
}

/// Checks one input and, if the check fails, panics with a reduced input.
pub fn assert_input(
    target: &str,
    base: &[u8],
    input: &[u8],
    check: &dyn Fn(&[u8]) -> Result<(), String>,
) {
    let Err(first) = verdict(check, input) else {
        return;
    };
    let minimal = reduce(base, input, &|candidate| verdict(check, candidate).is_err());
    let reason = verdict(check, &minimal).err().unwrap_or(first);
    panic!(
        "fuzz target {target} failed: {reason}\n  {}\n  input: {}",
        difference(base, &minimal),
        hex(&minimal)
    );
}

/// Removes steps of a failing sequence for as long as it still fails.
pub fn reduce_steps<T: Clone>(steps: &[T], fails: &dyn Fn(&[T]) -> bool) -> Vec<T> {
    let mut current = steps.to_vec();
    let mut step = current.len();
    let mut attempts = 0;
    while step > 0 && attempts < REDUCTION_ATTEMPTS {
        let mut start = 0;
        while start < current.len() && attempts < REDUCTION_ATTEMPTS {
            let end = (start + step).min(current.len());
            let mut candidate = current.clone();
            candidate.drain(start..end);
            attempts += 1;
            if fails(&candidate) {
                current = candidate;
            } else {
                start = end;
            }
        }
        if step == 1 {
            break;
        }
        step = step.div_ceil(2);
    }
    current
}
