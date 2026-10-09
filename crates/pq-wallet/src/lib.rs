//! Experimental wallet foundation. Payments, storage, recovery and CLI follow
//! the frozen wallet contract and are not implemented by this key checkpoint.

#![forbid(unsafe_code)]

/// Whether this build contains the experimental wallet key implementation.
pub const fn supports_experimental_slh_dsa_b128s() -> bool {
    cfg!(feature = "experimental-slh-dsa-b128s")
}

/// Explicit refusal for builds without the experimental wallet feature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExperimentalFeatureDisabled;

impl std::fmt::Display for ExperimentalFeatureDisabled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("experimental SLH wallet support is disabled")
    }
}

impl std::error::Error for ExperimentalFeatureDisabled {}

/// Check support before dispatching an SLH operation.
pub fn require_experimental_slh_dsa_b128s() -> Result<(), ExperimentalFeatureDisabled> {
    if supports_experimental_slh_dsa_b128s() {
        Ok(())
    } else {
        Err(ExperimentalFeatureDisabled)
    }
}

#[cfg(feature = "experimental-slh-dsa-b128s")]
mod keys;
#[cfg(feature = "experimental-slh-dsa-b128s")]
pub use keys::{KeyPath, Role, Root, RootEntropyError};

#[cfg(test)]
mod tests {
    #[test]
    fn disabled_feature_is_explicit() {
        assert_eq!(
            super::require_experimental_slh_dsa_b128s().is_ok(),
            cfg!(feature = "experimental-slh-dsa-b128s")
        );
    }
}
