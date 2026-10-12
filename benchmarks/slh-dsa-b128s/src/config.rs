//! Strict, bounded arguments. Parsing never performs cryptographic work.

pub const MAX_SAMPLES: u32 = 10_000;
pub const MAX_WARMUP: u32 = 1_000;

pub const HELP: &str = "tpq-bench list\n\
tpq-bench check-metadata\n\
tpq-bench measure --case keygen|sign|verify|verify-invalid --samples N --warmup N \
--cache-mode repeated-input|varied-input --execute\n\n\
Measurement is a human-run workload. No command measures by default.\n\
samples: 1..10000; warmup: 0..1000. Warmups are recorded, excluded from summaries.\n\
repeated-input reuses a public seed/key/message; signing always uses fresh OS entropy.\n\
varied-input varies public keygen seeds or messages; signing/verification reuse one key.\n\
Neither mode flushes processor or OS caches. Verification fixtures are signed untimed.";

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    List,
    Metadata,
    Help,
    Measure(Config),
}

pub fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Command, String> {
    let mut arguments = arguments.into_iter();
    let command = arguments
        .next()
        .ok_or("a command is required; use --help")?;
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
}
