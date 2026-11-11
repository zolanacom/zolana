//! Serial commands over a parent-owned pipe; only the public prover is retained.
//! Every request unlocks its wallet afresh and keeps the ordinary CLI checks.
use crate::{connection::TesterProfile, keys, payments::ProverPreparation, Result};
use serde::{de, Deserialize, Deserializer};
use serde_json::json;
use std::{
    collections::BTreeSet,
    fmt,
    io::{self, IsTerminal, Read, Write},
    os::fd::AsFd,
    path::Path,
};
use zeroize::Zeroizing;

const MAX_FRAME_BYTES: usize = 16 * 1024;
const MAX_ARGS: usize = 16;
const MAX_ARGUMENT_BYTES: usize = 2048;
const MAX_ARGUMENT_TOTAL_BYTES: usize = 8192;
const MAX_PASSWORD_BYTES: usize = 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    args: Vec<String>,
    #[serde(deserialize_with = "password_bytes")]
    password: Zeroizing<Vec<u8>>,
}

// Deserialize directly into zeroizing storage, including partially rejected
// arrays. The entire raw JSON frame is independently zeroized after each call.
fn password_bytes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Zeroizing<Vec<u8>>, D::Error> {
    struct PasswordVisitor;
    impl<'de> de::Visitor<'de> for PasswordVisitor {
        type Value = Zeroizing<Vec<u8>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a bounded UTF-8 password byte array")
        }

        fn visit_seq<A: de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut password = Zeroizing::new(Vec::with_capacity(MAX_PASSWORD_BYTES));
            while let Some(byte) = sequence.next_element::<u8>()? {
                if password.len() == MAX_PASSWORD_BYTES {
                    return Err(de::Error::custom("password exceeds the session bound"));
                }
                password.push(byte);
            }
            std::str::from_utf8(&password)
                .map_err(|_| de::Error::custom("session password must be UTF-8"))?;
            keys::validate_password(&password)
                .map_err(|_| de::Error::custom("invalid session password length"))?;
            Ok(password)
        }
    }
    deserializer.deserialize_seq(PasswordVisitor)
}

struct Bindings {
    network: String,
    wallet: String,
}

impl Bindings {
    fn load(network: &Path, wallet: &Path) -> Result<Self> {
        let profile = TesterProfile::load(network)?;
        if profile.private_send_transport.as_deref() != Some("native-inline-v1") {
            return Err("command-session requires an explicit native tester profile".into());
        }
        let bounded_path = |path: &Path| -> Result<String> {
            let value = path.to_str().ok_or("session paths must be UTF-8")?;
            if value.is_empty() || value.len() > MAX_ARGUMENT_BYTES || value.contains('\0') {
                return Err("invalid command-session path".into());
            }
            Ok(value.into())
        };
        Ok(Self {
            network: bounded_path(network)?,
            wallet: bounded_path(wallet)?,
        })
    }

    fn arguments(&self, requested: &[String]) -> Result<Vec<String>> {
        if requested.is_empty()
            || requested.len() > MAX_ARGS
            || requested.iter().any(|argument| {
                argument.is_empty()
                    || argument.len() > MAX_ARGUMENT_BYTES
                    || argument.contains('\0')
            })
            || requested.iter().map(String::len).sum::<usize>() > MAX_ARGUMENT_TOTAL_BYTES
        {
            return Err("invalid or oversized command-session arguments".into());
        }
        let command = requested[0].as_str();
        if !matches!(command, "balance" | "fees" | "send" | "resolve") {
            return Err("command is not allowed in a native wallet session".into());
        }
        let mut flags = BTreeSet::new();
        let pairs = &requested[1..];
        if !pairs.len().is_multiple_of(2) {
            return Err("command-session options require paired values".into());
        }
        for pair in pairs.chunks_exact(2) {
            let flag = pair[0].as_str();
            let value = pair[1].as_str();
            let allowed = match command {
                "send" => matches!(
                    flag,
                    "--amount" | "--to" | "--fee-payer" | "--max-shielded-fee"
                ),
                "fees" => flag == "--payment" && value == "send",
                _ => false,
            };
            if !allowed || !flags.insert(flag) {
                return Err("forbidden or duplicate command-session option".into());
            }
            if flag == "--fee-payer" && value != "shielded" {
                return Err("native command-session sends require shielded fees".into());
            }
        }
        let mut args = requested.to_vec();
        if command == "fees" && !flags.contains("--payment") {
            args.extend(["--payment".into(), "send".into()]);
        }
        args.extend([
            "--network".into(),
            self.network.clone(),
            "--wallet".into(),
            self.wallet.clone(),
            "--password-file".into(),
            "-".into(),
        ]);
        Ok(args)
    }
}

fn event(output: &mut impl Write, value: serde_json::Value) -> Result<()> {
    serde_json::to_writer(&mut *output, &value)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

fn session_error(output: &mut impl Write, error: impl fmt::Display) -> Result<()> {
    event(
        output,
        json!({"session_error":true,"error":error.to_string()}),
    )
}

// Read exactly one frame without an intermediate or read-ahead buffer. In
// particular, std's process-global buffered stdin must never hold a password.
fn read_frame(input: &mut impl Read) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut line = Zeroizing::new(Vec::with_capacity(MAX_FRAME_BYTES + 1));
    let mut byte = Zeroizing::new([0u8; 1]);
    loop {
        match input.read(&mut byte[..]) {
            Ok(0) => return Ok(line),
            Ok(_) => {
                line.push(byte[0]);
                if byte[0] == b'\n' || line.len() > MAX_FRAME_BYTES {
                    return Ok(line);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

fn serve_requests(
    input: &mut impl Read,
    output: &mut impl Write,
    bindings: &Bindings,
    mut handler: impl FnMut(Vec<String>, Option<&[u8]>) -> Result<()>,
) -> Result<()> {
    loop {
        let line = read_frame(input)?;
        if line.is_empty() {
            return Ok(());
        }
        if line.len() > MAX_FRAME_BYTES {
            session_error(
                output,
                "command-session frame exceeds its bound; session closed",
            )?;
            return Ok(());
        }
        if line.last() != Some(&b'\n') {
            session_error(output, "incomplete command-session frame; session closed")?;
            return Ok(());
        }
        let request: Request = match serde_json::from_slice(&line) {
            Ok(request) => request,
            Err(_) => {
                // Never echo parser errors: an invalid value might be a secret.
                session_error(output, "invalid command-session request")?;
                continue;
            }
        };
        let args = match bindings.arguments(&request.args) {
            Ok(args) => args,
            Err(error) => {
                session_error(output, error)?;
                continue;
            }
        };
        // Exactly one call per frame. In particular, a send error is returned
        // without retries; durable pending recovery remains an explicit command.
        if let Err(error) = handler(args, Some(&request.password)) {
            session_error(output, error)?;
        }
        output.flush()?;
    }
}

/// Serve a single wallet/profile binding over the parent process's pipes.
/// This creates no socket or listener and never retains a request password.
/// The handler must produce the ordinary command's single JSON result on stdout.
pub fn serve(
    network: &Path,
    wallet: &Path,
    mut handler: impl FnMut(Vec<String>, Option<&[u8]>) -> Result<()>,
) -> Result<()> {
    if io::stdin().is_terminal() || io::stdout().is_terminal() {
        return Err("command-session requires parent-owned input and output pipes".into());
    }
    let bindings = Bindings::load(network, wallet)?;
    let mut output = io::stdout();
    event(
        &mut output,
        json!({"session_ready":true,"format":"native-wallet-command-session-v1",
            "public_key_only":true,"proof_key_prepared":false,
            "proof_key_preparation":"after-first-command"}),
    )?;
    // Clone only the underlying descriptor, bypassing Stdin's global BufReader.
    // File::read is unbuffered, and read_frame never asks it for read-ahead data.
    let mut input = std::fs::File::from(io::stdin().as_fd().try_clone_to_owned()?);
    // A balance read requires a verification key, not a proving key. Prepare
    // public spending material after the first command, so cold restoration
    // can start immediately. This owned worker is joined on every exit.
    let mut preparation = None;
    serve_requests(&mut input, &mut output, &bindings, |args, password| {
        let result = handler(args, password);
        if preparation.is_none() {
            // Optional prefetch cannot replace an already produced command
            // result with an error. Payments still require their own checked
            // preparation before constructing a proof.
            preparation = ProverPreparation::start().ok();
        }
        result
    })?;
    if let Some(preparation) = preparation {
        preparation.finish()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn bindings() -> Bindings {
        Bindings {
            network: "/fixed/network.json".into(),
            wallet: "/fixed/wallet.json".into(),
        }
    }

    fn request(args: &[&str], password: &[u8]) -> Vec<u8> {
        let mut raw = serde_json::to_vec(&json!({"args":args,"password":password})).unwrap();
        raw.push(b'\n');
        raw
    }

    fn errors(raw: &[u8]) -> Vec<serde_json::Value> {
        std::str::from_utf8(raw)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn frame_reader_never_reads_ahead_or_uses_a_nonzeroizing_stdin_buffer() {
        struct OneByteReader {
            bytes: Vec<u8>,
            consumed: usize,
        }
        impl Read for OneByteReader {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                assert_eq!(
                    output.len(),
                    1,
                    "frame reader requested a read-ahead buffer"
                );
                let Some(byte) = self.bytes.get(self.consumed) else {
                    return Ok(0);
                };
                output[0] = *byte;
                self.consumed += 1;
                Ok(1)
            }
        }
        let first = request(&["balance"], b"first-test-password");
        let second = request(&["resolve"], b"second-test-password");
        let mut reader = OneByteReader {
            bytes: [first.as_slice(), second.as_slice()].concat(),
            consumed: 0,
        };
        assert_eq!(
            read_frame(&mut reader).unwrap().as_slice(),
            first.as_slice()
        );
        assert_eq!(reader.consumed, first.len());
        assert_eq!(
            read_frame(&mut reader).unwrap().as_slice(),
            second.as_slice()
        );
        assert_eq!(reader.consumed, first.len() + second.len());
        assert!(read_frame(&mut reader).unwrap().is_empty());
    }

    #[test]
    fn session_binds_public_paths_and_supplies_only_current_password() {
        let password = b"current-test-password";
        let input = request(&["balance"], password);
        let mut output = Vec::new();
        let mut calls = 0;
        serve_requests(
            &mut Cursor::new(input),
            &mut output,
            &bindings(),
            |args, secret| {
                calls += 1;
                assert_eq!(secret, Some(password.as_slice()));
                assert_eq!(
                    args,
                    vec![
                        "balance",
                        "--network",
                        "/fixed/network.json",
                        "--wallet",
                        "/fixed/wallet.json",
                        "--password-file",
                        "-"
                    ]
                );
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(calls, 1);
        assert!(output.is_empty());
    }

    #[test]
    fn session_rejects_operator_paths_and_non_native_commands() {
        for args in [
            vec!["deposit"],
            vec!["withdraw"],
            vec!["init"],
            vec!["reclaim"],
            vec!["balance", "--network", "/other"],
            vec!["balance", "--wallet", "/other"],
            vec!["balance", "--password-file", "/secret"],
            vec!["send", "--sponsor", "/operator"],
            vec!["send", "--rpc", "https://other"],
            vec!["send", "--history", "/history"],
            vec!["send", "--fee-payer", "user"],
            vec!["send", "--amount", "1", "--amount", "2"],
            vec!["send", "--amount"],
            vec!["fees", "--payment", "withdraw"],
        ] {
            let mut output = Vec::new();
            let input = request(&args, b"valid-test-password");
            serve_requests(&mut Cursor::new(input), &mut output, &bindings(), |_, _| {
                panic!("forbidden request reached the command handler")
            })
            .unwrap();
            assert_eq!(errors(&output).len(), 1, "{args:?}");
            assert_eq!(errors(&output)[0]["session_error"], true);
        }
    }

    #[test]
    fn send_failure_is_reported_once_and_never_retried() {
        let mut input = request(
            &[
                "send",
                "--amount",
                "1",
                "--to",
                "recipient",
                "--max-shielded-fee",
                "3000000",
            ],
            b"first-test-password",
        );
        input.extend(request(&["resolve"], b"second-test-password"));
        let mut output = Vec::new();
        let mut commands = Vec::new();
        serve_requests(
            &mut Cursor::new(input),
            &mut output,
            &bindings(),
            |args, password| {
                commands.push(args[0].clone());
                if args[0] == "send" {
                    assert_eq!(password, Some(b"first-test-password".as_slice()));
                    Err("connection lost; pending retained".into())
                } else {
                    assert_eq!(password, Some(b"second-test-password".as_slice()));
                    Ok(())
                }
            },
        )
        .unwrap();
        assert_eq!(commands, ["send", "resolve"]);
        let result = errors(&output);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["error"], "connection lost; pending retained");
    }

    #[test]
    fn invalid_passwords_and_unknown_fields_never_echo_secret_input() {
        let secrets = [vec![b'x'; 11], vec![b'x'; 1025], vec![255; 12]];
        let mut input = Vec::new();
        for secret in secrets {
            input.extend(request(&["balance"], &secret));
        }
        input.extend(b"{\"args\":[\"balance\"],\"password\":\"do-not-echo-this-secret\"}\n");
        input.extend(b"{\"args\":[\"balance\"],\"password\":[120,120,120,120,120,120,120,120,120,120,120,120],\"extra\":true}\n");
        input.extend(request(&["balance"], b"valid-test-password"));
        let mut output = Vec::new();
        let mut calls = 0;
        serve_requests(&mut Cursor::new(input), &mut output, &bindings(), |_, _| {
            calls += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(errors(&output).len(), 5);
        assert!(!String::from_utf8(output).unwrap().contains("do-not-echo"));
    }

    #[test]
    fn oversized_and_incomplete_frames_close_without_processing_a_suffix() {
        for mut input in [
            vec![b' '; MAX_FRAME_BYTES + 1],
            b"{\"args\":[\"balance\"]}".to_vec(),
        ] {
            if input.len() > MAX_FRAME_BYTES {
                input.push(b'\n');
                input.extend(request(&["balance"], b"valid-test-password"));
            }
            let mut output = Vec::new();
            serve_requests(&mut Cursor::new(input), &mut output, &bindings(), |_, _| {
                panic!("invalid frame reached the command handler")
            })
            .unwrap();
            assert_eq!(errors(&output).len(), 1);
            assert_eq!(errors(&output)[0]["session_error"], true);
        }
    }

    #[test]
    fn native_fee_request_defaults_to_private_send_quote() {
        let arguments = bindings().arguments(&["fees".into()]).unwrap();
        assert_eq!(&arguments[..3], ["fees", "--payment", "send"]);
    }

    #[test]
    fn argument_count_size_and_nul_are_bounded() {
        for args in [
            vec!["balance".into(); MAX_ARGS + 1],
            vec![
                "send".into(),
                "--to".into(),
                "x".repeat(MAX_ARGUMENT_BYTES + 1),
            ],
            vec!["send".into(), "--to".into(), "hidden\0suffix".into()],
        ] {
            assert!(bindings().arguments(&args).is_err());
        }
    }
}
