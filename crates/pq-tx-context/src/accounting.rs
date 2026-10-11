//! Logical serialization sizes; no native-output recognition or admission rules.

use zakura_chain::{serialization::CompactSizeMessage, transparent::Output};

/// An accounting failure, separate from capacity exhaustion or consensus validity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ContextAccountingError {
    /// The ordered outputs must match all inputs, and none may be coinbase.
    #[error("expected one resolved output per non-coinbase input")]
    InputContext,
    /// An in-memory script exceeds the backend's serialization length bound.
    #[error("spent-output script length cannot be serialized by the backend")]
    ScriptLength,
    /// A size or counter cannot be represented as a `u64`.
    #[error("spent-output accounting overflow")]
    Overflow,
}

/// Read a script length after enforcing the backend's serialization bound.
/// This is not the legacy execution limit or an allocation allowance.
pub fn checked_script_len(output: &Output) -> Result<u64, ContextAccountingError> {
    let script_len = output.lock_script.as_raw_bytes().len();
    CompactSizeMessage::try_from(script_len).map_err(|_| ContextAccountingError::ScriptLength)?;
    u64::try_from(script_len).map_err(|_| ContextAccountingError::Overflow)
}

/// Amount, CompactSize length and script bytes, without an outer vector prefix.
///
/// This arithmetic helper handles all `u64` lengths and checked overflow. For
/// actual outputs, first use [`checked_script_len`] to enforce the backend bound.
pub fn output_bytes(script_len: u64) -> Result<u64, ContextAccountingError> {
    let prefix = match script_len {
        0..=252 => 1,
        253..=65_535 => 3,
        65_536..=0xffff_ffff => 5,
        _ => 9,
    };
    script_len
        .checked_add(8 + prefix)
        .ok_or(ContextAccountingError::Overflow)
}
