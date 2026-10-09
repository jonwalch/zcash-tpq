//! Deterministic, explicitly public test fixtures only. Never use wallet secrets.

#![forbid(unsafe_code)]

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};
use slh_dsa::{Blake3_128s, SigningKey};

const CONTRACT: &str = "slh-dsa-b-128s-exp-v1";
const SCHEMA_VERSION: u32 = 1;
const MAX_REQUEST_BYTES: u64 = 32_768;
const MAX_RESPONSE_BYTES: usize = 32_768;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
enum Request {
    Keygen {
        version: u32,
        contract: String,
        public_fixture: bool,
        seed: String,
    },
    Sign {
        version: u32,
        contract: String,
        public_fixture: bool,
        secret_key: String,
        message: String,
        randomizer: String,
    },
}

// No Debug or serialization implementation is provided for decoded requests.
enum CheckedRequest {
    Keygen {
        seed: [u8; 48],
    },
    Sign {
        secret_key: [u8; 64],
        message: [u8; 101],
        randomizer: [u8; 16],
    },
}

#[derive(Serialize)]
struct Backend {
    repository: &'static str,
    revision: &'static str,
    blake3: &'static str,
}

#[derive(Serialize)]
struct Response {
    version: u32,
    contract: &'static str,
    public_fixture: bool,
    material: &'static str,
    backend: Backend,
    public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    locally_verified: Option<bool>,
}

impl Response {
    fn new(public_key: String) -> Self {
        Self {
            version: SCHEMA_VERSION,
            contract: CONTRACT,
            public_fixture: true,
            material: "public-test-only",
            backend: Backend {
                repository: "https://github.com/PQC-Suite-B/signatures",
                revision: "b392fe82d2d9770142477a576a758a233888bc0a",
                blake3: "1.8.5",
            },
            public_key,
            secret_key: None,
            signature: None,
            locally_verified: None,
        }
    }
}

fn decode<const N: usize>(encoded: &str) -> Result<[u8; N], &'static str> {
    if encoded.len() != N * 2 {
        return Err("incorrect encoded field length");
    }
    let mut decoded = [0; N];
    hex::decode_to_slice(encoded, &mut decoded).map_err(|_| "invalid hex field")?;
    Ok(decoded)
}

fn envelope(version: u32, contract: &str, public: bool) -> Result<(), &'static str> {
    if version != SCHEMA_VERSION || contract != CONTRACT || !public {
        return Err("schema, contract or public-fixture declaration mismatch");
    }
    Ok(())
}

fn validate(request: Request) -> Result<CheckedRequest, &'static str> {
    match request {
        Request::Keygen {
            version,
            contract,
            public_fixture,
            seed,
        } => {
            envelope(version, &contract, public_fixture)?;
            Ok(CheckedRequest::Keygen {
                seed: decode(&seed)?,
            })
        }
        Request::Sign {
            version,
            contract,
            public_fixture,
            secret_key,
            message,
            randomizer,
        } => {
            envelope(version, &contract, public_fixture)?;
            Ok(CheckedRequest::Sign {
                secret_key: decode(&secret_key)?,
                message: decode(&message)?,
                randomizer: decode(&randomizer)?,
            })
        }
    }
}

fn execute(request: CheckedRequest) -> Result<Response, &'static str> {
    match request {
        CheckedRequest::Keygen { seed } => {
            let key = SigningKey::<Blake3_128s>::slh_keygen_internal(
                &seed[..16],
                &seed[16..32],
                &seed[32..],
            );
            let mut response = Response::new(hex::encode(key.as_ref().to_bytes()));
            response.secret_key = Some(hex::encode(key.to_bytes()));
            Ok(response)
        }
        CheckedRequest::Sign {
            secret_key,
            message,
            randomizer,
        } => {
            let key = SigningKey::<Blake3_128s>::try_from(secret_key.as_slice())
                .map_err(|_| "invalid public fixture signing key")?;
            let signature = key
                .try_sign_with_context(&message, &[], Some(&randomizer))
                .map_err(|_| "public fixture signing failed")?;
            key.as_ref()
                .try_verify_with_context(&message, &[], &signature)
                .map_err(|_| "upstream post-sign verification failed")?;
            let public_key = key.as_ref().to_bytes();
            let signature = signature.to_bytes();
            zakura_pq_slh_dsa_b_verify::verify(&public_key, &signature, &message, &[])
                .map_err(|_| "extracted post-sign verification failed")?;
            let mut response = Response::new(hex::encode(public_key));
            response.signature = Some(hex::encode(signature));
            response.locally_verified = Some(true);
            Ok(response)
        }
    }
}

fn read_request(reader: impl Read) -> Result<CheckedRequest, &'static str> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "request read failed")?;
    if u64::try_from(bytes.len()).map_err(|_| "request length overflow")? > MAX_REQUEST_BYTES {
        return Err("request exceeds 32768 bytes");
    }
    let request = serde_json::from_slice(&bytes).map_err(|_| "invalid request schema")?;
    validate(request)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let result = if std::env::var_os("CREATE_VECTOR_SET").is_some() {
        Err("CREATE_VECTOR_SET must be absent")
    } else {
        read_request(io::stdin().lock()).and_then(execute)
    };
    let output = match result {
        Ok(response) => serde_json::to_vec(&response)?,
        Err(error) => serde_json::to_vec(&serde_json::json!({ "error": error }))?,
    };
    // Account for the terminal newline as part of the encoded response bound.
    if output.len() >= MAX_RESPONSE_BYTES {
        return Err("response exceeds 32768 bytes".into());
    }
    let mut stdout = io::stdout().lock();
    stdout.write_all(&output)?;
    writeln!(stdout)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn request(op: &str) -> Value {
        json!({"version":1,"contract":CONTRACT,"public_fixture":true,"op":op})
    }

    fn checked(value: &Value) -> Result<CheckedRequest, &'static str> {
        read_request(serde_json::to_vec(value).unwrap().as_slice())
    }

    #[test]
    fn rejects_before_crypto() {
        let mut keygen = request("keygen");
        keygen["seed"] = json!("00".repeat(48));
        assert!(checked(&keygen).is_ok());
        for (field, value) in [
            ("public_fixture", json!(false)),
            ("version", json!(2)),
            ("contract", json!("hash-four-payments-v1")),
            ("seed", json!("00".repeat(47))),
            ("seed", json!("00".repeat(49))),
            ("seed", json!("gg".repeat(48))),
            ("internal", json!(true)),
            ("profile", json!("b128s")),
            ("repeats", json!(1)),
        ] {
            let mut altered = keygen.clone();
            altered[field] = value;
            assert!(checked(&altered).is_err(), "{field}");
        }
        let mut sign = request("sign");
        sign["secret_key"] = json!("00".repeat(64));
        sign["message"] = json!("00".repeat(101));
        sign["randomizer"] = json!("00".repeat(16));
        assert!(checked(&sign).is_ok());
        for (field, length) in [
            ("secret_key", 63),
            ("secret_key", 65),
            ("message", 100),
            ("message", 102),
            ("randomizer", 15),
            ("randomizer", 17),
        ] {
            let mut altered = sign.clone();
            altered[field] = json!("00".repeat(length));
            assert!(checked(&altered).is_err(), "{field}/{length}");
        }
        sign["context"] = json!("");
        assert!(checked(&sign).is_err());
        assert!(read_request(&vec![b' '; 32_769][..]).is_err());
        assert!(read_request(b"{}".as_slice()).is_err());
    }

    #[test]
    fn retained_independent_keygen_and_new_contract_signing() {
        let case: Value =
            serde_json::from_str(include_str!("../tests/public-keygen.json")).unwrap();
        let response = execute(CheckedRequest::Keygen {
            seed: decode(case["seed"].as_str().unwrap()).unwrap(),
        })
        .unwrap();
        assert_eq!(response.public_key, case["public_key"].as_str().unwrap());
        assert_eq!(response.secret_key.as_deref(), case["secret_key"].as_str());
        let mut message = Vec::from(b"ZcashTransparentPQ/experimental/slh-dsa-b-128s/message/v1\0");
        message.extend_from_slice(&[0xf7, 2, 5]);
        message.extend_from_slice(&0x77190ad9u32.to_le_bytes());
        message.extend_from_slice(&0u32.to_le_bytes());
        message.extend_from_slice(&[0x42; 32]);
        let message: [u8; 101] = message.try_into().unwrap();
        let mut secret_key = decode(response.secret_key.as_deref().unwrap()).unwrap();
        let signed = execute(CheckedRequest::Sign {
            secret_key,
            message,
            randomizer: [0x24; 16],
        })
        .unwrap();
        assert_eq!(signed.public_key, response.public_key);
        assert_eq!(signed.signature.unwrap().len(), 7856 * 2);
        assert_eq!(signed.locally_verified, Some(true));
        assert!(signed.secret_key.is_none());
        secret_key[48] ^= 1;
        assert!(
            execute(CheckedRequest::Sign {
                secret_key,
                message,
                randomizer: [0x24; 16],
            })
            .is_err()
        );
    }
}
