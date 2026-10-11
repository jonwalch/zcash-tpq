//! Stable verifier identity for build receipts; querying it never verifies a signature.

/// The compiled SLH verifier and the separately gated complete runtime.
///
/// Source, executable and configuration hashes belong in the external build
/// receipt. This identity describes the selected contract and backend only.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ExperimentalSlhDsaB128sVerifierIdentity {
    /// Identity schema version.
    pub schema_version: u8,
    /// Experimental signing contract.
    pub contract: &'static str,
    /// Experiment-local suite byte in lowercase hexadecimal.
    pub suite_id: &'static str,
    /// Portable verifier, or `disabled` when it is absent from this build.
    pub backend: &'static str,
    /// Pinned algorithm source used by the attributable verifier extraction.
    pub algorithm_revision: &'static str,
    /// Exact hash dependency selected by the verifier.
    pub blake3_version: &'static str,
    /// Whether this build contains the SLH verifier.
    pub verifier_compiled: bool,
    /// Whether configured node startup is supported by the integrated runtime.
    pub runtime_supported: bool,
}

/// Describe this build without initializing node services or executing cryptography.
pub const fn experimental_slh_dsa_b128s_verifier_identity(
) -> ExperimentalSlhDsaB128sVerifierIdentity {
    ExperimentalSlhDsaB128sVerifierIdentity {
        schema_version: 1,
        contract: "slh-dsa-b-128s-exp-v1",
        suite_id: "f7",
        backend: if cfg!(feature = "experimental-slh-dsa-b128s") {
            "portable-rust"
        } else {
            "disabled"
        },
        algorithm_revision: "b392fe82d2d9770142477a576a758a233888bc0a",
        blake3_version: "1.8.5",
        verifier_compiled: cfg!(feature = "experimental-slh-dsa-b128s"),
        runtime_supported: crate::supports_experimental_slh_dsa_b128s(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn slh_verifier_identity_distinguishes_compiled_verifier_and_runtime() {
        let identity = super::experimental_slh_dsa_b128s_verifier_identity();
        let json = serde_json::to_value(identity).unwrap();
        assert_eq!(json.as_object().unwrap().len(), 8);
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["contract"], "slh-dsa-b-128s-exp-v1");
        assert_eq!(json["suite_id"], "f7");
        assert_eq!(
            json["algorithm_revision"],
            "b392fe82d2d9770142477a576a758a233888bc0a"
        );
        assert_eq!(json["blake3_version"], "1.8.5");
        assert_eq!(
            json["verifier_compiled"],
            cfg!(feature = "experimental-slh-dsa-b128s")
        );
        assert_eq!(
            json["runtime_supported"],
            crate::supports_experimental_slh_dsa_b128s()
        );
        assert_eq!(
            identity.runtime_supported,
            cfg!(feature = "experimental-slh-dsa-b128s")
        );
        if identity.verifier_compiled {
            assert_eq!(identity.backend, "portable-rust");
        } else {
            assert_eq!(identity.backend, "disabled");
            assert!(!identity.runtime_supported);
        }
        #[cfg(feature = "experimental-slh-dsa-b128s")]
        {
            assert_eq!(
                identity.contract,
                zakura_pq_slh_dsa_b_exp::contract::CONTRACT
            );
            assert_eq!(
                identity.suite_id,
                format!("{:02x}", zakura_pq_slh_dsa_b_exp::contract::SUITE)
            );
        }
    }
}
