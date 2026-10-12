//! Strict, bounded arguments. Parsing never performs cryptographic work.

use std::path::PathBuf;

pub const MAX_SAMPLES: u32 = 10_000;
pub const MAX_WARMUP: u32 = 1_000;
pub const MAX_PAYMENT_SAMPLES: u32 = 100;
pub const MAX_PAYMENT_WARMUP: u32 = 10;

pub const HELP: &str = "tpq-bench list\n\
tpq-bench check-metadata\n\
tpq-bench measure --case keygen|sign|verify|verify-invalid --samples N --warmup N \
--cache-mode repeated-input|varied-input --execute\n\
tpq-bench payment --algorithm slh-dsa-b128s|ecdsa-secp256k1 --version v5|v6 \
--policy single|multisig --inputs 1|2|5 --inventory cached|generated \
--samples N --warmup N --artifact-directory PATH --wallet-storage-root PATH --execute\n\n\
tpq-bench check-payment --algorithm slh-dsa-b128s|ecdsa-secp256k1 --version v5|v6 \
--policy single|multisig --inputs 1|2|5 --inventory cached|generated \
--artifact-directory PATH --wallet-storage-root PATH\n\n\
Measurement is a human-run workload. No command measures by default.\n\
samples: 1..10000; warmup: 0..1000. Warmups are recorded, excluded from summaries.\n\
One additional final process record reports a lifetime peak through that snapshot.\n\
repeated-input reuses a public seed/key/message; signing always uses fresh OS entropy.\n\
varied-input varies public keygen seeds or messages; signing/verification reuse one key.\n\
Neither mode flushes processor or OS caches. Verification fixtures are signed untimed.\n\
Payments are disposable offline fixtures, never authenticated chain funding.\n\
Payment bounds: samples 1..100, warmup 0..10; artifacts contain public bytes only.\n\
Wallet storage uses an explicit existing directory; TMPDIR does not select its filesystem.\n\
single means 1-of-1; multisig means 2-of-3. Inventory caching is not secret-key caching.\n\
SLH foreground includes real wallet preparation, signing and assembly with durable journals.\n\
Classical controls measure transaction assembly/signing/verification, not the SLH wallet.";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    Slh,
    Classical,
}

impl Algorithm {
    pub fn name(self) -> &'static str {
        match self {
            Self::Slh => "slh-dsa-b128s",
            Self::Classical => "ecdsa-secp256k1",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentConfig {
    pub algorithm: Algorithm,
    pub version: u8,
    pub multisig: bool,
    pub inputs: usize,
    pub generated: bool,
    pub samples: u32,
    pub warmup: u32,
    pub artifact_directory: PathBuf,
    pub wallet_storage_root: PathBuf,
}

impl PaymentConfig {
    pub fn inventory(&self) -> &'static str {
        if self.generated {
            "generated"
        } else {
            "cached"
        }
    }

    pub fn policy(&self) -> &'static str {
        if self.multisig {
            "multisig"
        } else {
            "single"
        }
    }

    pub fn case_id(&self) -> String {
        format!(
            "payment.{}.v{}.{}.i{}.{}",
            self.algorithm.name(),
            self.version,
            self.policy(),
            self.inputs,
            self.inventory()
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Case {
    Keygen,
    Sign,
    Verify,
    VerifyInvalid,
}

impl Case {
    pub const ALL: [Self; 4] = [Self::Keygen, Self::Sign, Self::Verify, Self::VerifyInvalid];

    pub fn name(self) -> &'static str {
        match self {
            Self::Keygen => "keygen",
            Self::Sign => "sign",
            Self::Verify => "verify",
            Self::VerifyInvalid => "verify-invalid",
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            Self::Keygen => "primitive.keygen",
            Self::Sign => "primitive.sign",
            Self::Verify => "primitive.verify",
            Self::VerifyInvalid => "primitive.verify-invalid",
        }
    }

    pub fn timing_metric(self) -> &'static str {
        match self {
            Self::Keygen => "keygen_ns",
            Self::Sign => "sign_release_ns",
            Self::Verify | Self::VerifyInvalid => "signature_verify_ns",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheMode {
    RepeatedInput,
    VariedInput,
}

impl CacheMode {
    pub fn name(self) -> &'static str {
        match self {
            Self::RepeatedInput => "repeated-input",
            Self::VariedInput => "varied-input",
        }
    }

    pub fn input_index(self, attempt: u32) -> u32 {
        match self {
            Self::RepeatedInput => 0,
            Self::VariedInput => attempt + 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    pub case: Case,
    pub samples: u32,
    pub warmup: u32,
    pub cache_mode: CacheMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    List,
    Metadata,
    Help,
    Measure(Config),
    Payment(PaymentConfig),
    CheckPayment(PaymentConfig),
}

pub fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Command, String> {
    let mut arguments = arguments.into_iter();
    let command = arguments
        .next()
        .ok_or("a command is required; use --help")?;
    if command == "payment" {
        return parse_payment(arguments, true).map(Command::Payment);
    }
    if command == "check-payment" {
        return parse_payment(arguments, false).map(Command::CheckPayment);
    }
    let non_measuring = match command.as_str() {
        "list" => Some(Command::List),
        "check-metadata" => Some(Command::Metadata),
        "--help" | "-h" => Some(Command::Help),
        "measure" => None,
        _ => return Err(format!("unknown command: {command}")),
    };
    if let Some(command) = non_measuring {
        if arguments.next().is_some() {
            return Err("this command takes no arguments".into());
        }
        return Ok(command);
    }

    let (mut case, mut samples, mut warmup, mut cache_mode) = (None, None, None, None);
    let mut execute = false;
    while let Some(flag) = arguments.next() {
        if flag == "--execute" {
            if execute {
                return Err("duplicate --execute".into());
            }
            execute = true;
            continue;
        }
        if !matches!(
            flag.as_str(),
            "--case" | "--samples" | "--warmup" | "--cache-mode"
        ) {
            return Err(format!("unknown option: {flag}"));
        }
        let value = arguments
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--case" => set_once(
                &mut case,
                match value.as_str() {
                    "keygen" => Case::Keygen,
                    "sign" => Case::Sign,
                    "verify" => Case::Verify,
                    "verify-invalid" => Case::VerifyInvalid,
                    _ => return Err(format!("unknown case: {value}")),
                },
                &flag,
            )?,
            "--samples" => set_once(&mut samples, count(&value, 1, MAX_SAMPLES, &flag)?, &flag)?,
            "--warmup" => set_once(&mut warmup, count(&value, 0, MAX_WARMUP, &flag)?, &flag)?,
            "--cache-mode" => set_once(
                &mut cache_mode,
                match value.as_str() {
                    "repeated-input" => CacheMode::RepeatedInput,
                    "varied-input" => CacheMode::VariedInput,
                    _ => return Err(format!("unknown cache mode: {value}")),
                },
                &flag,
            )?,
            _ => unreachable!("unknown options were rejected before reading the value"),
        }
    }
    if !execute {
        return Err("measurement requires explicit --execute by a human".into());
    }
    Ok(Command::Measure(Config {
        case: case.ok_or("--case is required")?,
        samples: samples.ok_or("--samples is required")?,
        warmup: warmup.ok_or("--warmup is required")?,
        cache_mode: cache_mode.ok_or("--cache-mode is required")?,
    }))
}

fn parse_payment(
    mut arguments: impl Iterator<Item = String>,
    measure: bool,
) -> Result<PaymentConfig, String> {
    let (mut algorithm, mut version, mut multisig, mut inputs, mut generated) =
        (None, None, None, None, None);
    let (mut samples, mut warmup, mut artifact_directory) = (None, None, None);
    let mut wallet_storage_root = None;
    let mut execute = false;
    while let Some(flag) = arguments.next() {
        if !measure && matches!(flag.as_str(), "--execute" | "--samples" | "--warmup") {
            return Err(
                "check-payment is one untimed correctness case and accepts no measurement flags"
                    .into(),
            );
        }
        if flag == "--execute" {
            if execute {
                return Err("duplicate --execute".into());
            }
            execute = true;
            continue;
        }
        if !matches!(
            flag.as_str(),
            "--algorithm"
                | "--version"
                | "--policy"
                | "--inputs"
                | "--inventory"
                | "--samples"
                | "--warmup"
                | "--artifact-directory"
                | "--wallet-storage-root"
        ) {
            return Err(format!("unknown payment option: {flag}"));
        }
        let value = arguments
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--algorithm" => set_once(
                &mut algorithm,
                match value.as_str() {
                    "slh-dsa-b128s" => Algorithm::Slh,
                    "ecdsa-secp256k1" => Algorithm::Classical,
                    _ => return Err("algorithm must be slh-dsa-b128s or ecdsa-secp256k1".into()),
                },
                &flag,
            )?,
            "--version" => set_once(
                &mut version,
                match value.as_str() {
                    "v5" => 5,
                    "v6" => 6,
                    _ => return Err("version must be v5 or v6".into()),
                },
                &flag,
            )?,
            "--policy" => set_once(
                &mut multisig,
                match value.as_str() {
                    "single" => false,
                    "multisig" => true,
                    _ => return Err("policy must be single or multisig".into()),
                },
                &flag,
            )?,
            "--inputs" => set_once(
                &mut inputs,
                match value.as_str() {
                    "1" => 1,
                    "2" => 2,
                    "5" => 5,
                    _ => return Err("inputs must be 1, 2 or 5".into()),
                },
                &flag,
            )?,
            "--inventory" => set_once(
                &mut generated,
                match value.as_str() {
                    "cached" => false,
                    "generated" => true,
                    _ => return Err("inventory must be cached or generated".into()),
                },
                &flag,
            )?,
            "--samples" => set_once(
                &mut samples,
                count(&value, 1, MAX_PAYMENT_SAMPLES, &flag)?,
                &flag,
            )?,
            "--warmup" => set_once(
                &mut warmup,
                count(&value, 0, MAX_PAYMENT_WARMUP, &flag)?,
                &flag,
            )?,
            "--artifact-directory" => {
                if value.is_empty() {
                    return Err("artifact directory cannot be empty".into());
                }
                set_once(&mut artifact_directory, PathBuf::from(value), &flag)?;
            }
            "--wallet-storage-root" => {
                if value.is_empty() {
                    return Err("wallet storage root cannot be empty".into());
                }
                set_once(&mut wallet_storage_root, PathBuf::from(value), &flag)?;
            }
            _ => unreachable!("unknown payment options are rejected above"),
        }
    }
    if measure && !execute {
        return Err("payment measurement requires explicit --execute by a human".into());
    }
    Ok(PaymentConfig {
        algorithm: algorithm.ok_or("--algorithm is required")?,
        version: version.ok_or("--version is required")?,
        multisig: multisig.ok_or("--policy is required")?,
        inputs: inputs.ok_or("--inputs is required")?,
        generated: generated.ok_or("--inventory is required")?,
        samples: if measure {
            samples.ok_or("--samples is required")?
        } else {
            1
        },
        warmup: if measure {
            warmup.ok_or("--warmup is required")?
        } else {
            0
        },
        artifact_directory: artifact_directory.ok_or("--artifact-directory is required")?,
        wallet_storage_root: wallet_storage_root.ok_or("--wallet-storage-root is required")?,
    })
}

fn set_once<T>(slot: &mut Option<T>, value: T, flag: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("duplicate {flag}"));
    }
    Ok(())
}

fn count(value: &str, min: u32, max: u32, flag: &str) -> Result<u32, String> {
    let parsed = value
        .parse::<u32>()
        .map_err(|_| format!("{flag} must be an integer"))?;
    if !(min..=max).contains(&parsed) {
        return Err(format!("{flag} must be in {min}..={max}"));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(text: &str) -> Result<Command, String> {
        parse(text.split_whitespace().map(str::to_owned))
    }

    const VALID: &str =
        "measure --case verify --samples 10 --warmup 2 --cache-mode varied-input --execute";

    #[test]
    fn measurement_requires_all_bounds_and_explicit_execution() {
        assert_eq!(
            args(VALID),
            Ok(Command::Measure(Config {
                case: Case::Verify,
                samples: 10,
                warmup: 2,
                cache_mode: CacheMode::VariedInput,
            }))
        );
        for removed in [
            " --execute",
            " --samples 10",
            " --warmup 2",
            " --cache-mode varied-input",
            " --case verify",
        ] {
            assert!(args(&VALID.replace(removed, "")).is_err(), "{removed}");
        }
        assert!(args("").is_err());
        assert!(args("measure").is_err());
    }

    #[test]
    fn malformed_duplicate_unknown_and_excessive_options_are_rejected() {
        for replacement in [
            "--samples 0",
            "--samples 10001",
            "--samples -1",
            "--samples 1.5",
            "--samples 4294967296",
        ] {
            assert!(args(&VALID.replace("--samples 10", replacement)).is_err());
        }
        assert!(args(&VALID.replace("--warmup 2", "--warmup 1001")).is_err());
        assert!(args(&VALID.replace("varied-input", "cold")).is_err());
        for extra in [
            " --execute",
            " --samples 1",
            " --warmup 0",
            " --case sign",
            " --cache-mode repeated-input",
            " --unknown 1",
            " --samples",
        ] {
            assert!(args(&format!("{VALID}{extra}")).is_err(), "{extra}");
        }
    }

    #[test]
    fn inspection_commands_cannot_be_combined_with_measurement_flags() {
        assert_eq!(args("list"), Ok(Command::List));
        assert_eq!(args("check-metadata"), Ok(Command::Metadata));
        assert_eq!(args("--help"), Ok(Command::Help));
        assert!(args("list --execute").is_err());
        assert!(args("check-metadata measure").is_err());
        assert_eq!(CacheMode::RepeatedInput.input_index(10), 0);
        assert_eq!(CacheMode::VariedInput.input_index(10), 11);
    }

    const PAYMENT: &str = "payment --algorithm slh-dsa-b128s --version v6 --policy multisig --inputs 2 --inventory generated --samples 2 --warmup 1 --artifact-directory /tmp/public --wallet-storage-root /tmp/wallet-storage --execute";

    #[test]
    fn payment_parser_requires_bounded_explicit_dimensions() {
        let Command::Payment(config) = args(PAYMENT).unwrap() else {
            panic!("payment command")
        };
        assert_eq!(
            config.case_id(),
            "payment.slh-dsa-b128s.v6.multisig.i2.generated"
        );
        for missing in [
            " --algorithm slh-dsa-b128s",
            " --version v6",
            " --policy multisig",
            " --inputs 2",
            " --inventory generated",
            " --samples 2",
            " --warmup 1",
            " --artifact-directory /tmp/public",
            " --wallet-storage-root /tmp/wallet-storage",
            " --execute",
        ] {
            assert!(args(&PAYMENT.replace(missing, "")).is_err(), "{missing}");
        }
        for (from, to) in [
            ("--samples 2", "--samples 101"),
            ("--warmup 1", "--warmup 11"),
            ("--inputs 2", "--inputs 3"),
            ("--version v6", "--version 6"),
            ("--policy multisig", "--policy 15-of-15"),
            ("--inventory generated", "--inventory cold"),
            ("--algorithm slh-dsa-b128s", "--algorithm unknown"),
        ] {
            assert!(args(&PAYMENT.replace(from, to)).is_err(), "{to}");
        }
        for duplicate in [
            "--version v5",
            "--execute",
            "--inputs 1",
            "--artifact-directory /tmp/other",
            "--wallet-storage-root /tmp/other",
        ] {
            assert!(args(&format!("{PAYMENT} {duplicate}")).is_err());
        }
    }

    #[test]
    fn correctness_command_cannot_enable_performance_collection() {
        let check = PAYMENT
            .replacen("payment", "check-payment", 1)
            .replace(" --samples 2", "")
            .replace(" --warmup 1", "")
            .replace(" --execute", "");
        let Command::CheckPayment(config) = args(&check).unwrap() else {
            panic!("correctness command")
        };
        assert_eq!(config.samples, 1);
        assert_eq!(config.warmup, 0);
        for forbidden in ["--execute", "--samples 1", "--warmup 0"] {
            assert!(args(&format!("{check} {forbidden}")).is_err());
        }
    }
}
