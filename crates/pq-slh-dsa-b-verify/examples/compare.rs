//! Bounded public-verification adapter for independent conformance tools.
//!
//! One JSON object on stdin contains hex `public_key`, `signature`, `message`
//! and `context` fields. This example uses dev dependencies only.

use serde::Deserialize;
use std::io::{self, Read, Write};
use zakura_pq_slh_dsa_b_verify::{
    verify, MAX_CONTEXT_BYTES, MAX_MESSAGE_BYTES, PUBLIC_KEY_BYTES, SIGNATURE_BYTES,
};

const MAX_REQUEST_BYTES: u64 = 160_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    public_key: String,
    signature: String,
    message: String,
    context: String,
}

fn hex_decode(value: &str, maximum: usize) -> Result<Vec<u8>, &'static str> {
    if value.len() > 2 * (maximum + 1) || !value.len().is_multiple_of(2) {
        return Err("field exceeds adapter bound or has odd hex length");
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair).map_err(|_| "hex field must be ASCII")?;
            if !pair.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err("field contains invalid hex");
            }
            u8::from_str_radix(pair, 16).map_err(|_| "field contains invalid hex")
        })
        .collect()
}

fn run() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len())? > MAX_REQUEST_BYTES {
        return Err("request exceeds adapter bound".into());
    }
    let request: Request = serde_json::from_slice(&bytes)?;
    let pk = hex_decode(&request.public_key, PUBLIC_KEY_BYTES)?;
    let signature = hex_decode(&request.signature, SIGNATURE_BYTES)?;
    let message = hex_decode(&request.message, MAX_MESSAGE_BYTES)?;
    let context = hex_decode(&request.context, MAX_CONTEXT_BYTES)?;
    let result = verify(&pk, &signature, &message, &context);
    Ok(
        serde_json::json!({ "valid": result.is_ok(), "error": result.err().map(|error| format!("{error:?}")) }),
    )
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = match run() {
        Ok(output) => output,
        Err(error) => serde_json::json!({ "valid": false, "error": format!("Adapter: {error}") }),
    };
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &output)?;
    writeln!(stdout)?;
    Ok(())
}
