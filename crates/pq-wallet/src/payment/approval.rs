//! Proposal-ID framing and the gate before fresh or cached signature release.
//! Canonical serialization and hash-backend correctness are separate contracts.

pub fn proposal_id<E, F, H>(encode: F, hash: H) -> Result<[u8; 32], E>
where
    F: FnOnce() -> Result<Vec<u8>, E>,
    H: FnOnce(&[u8], &[u8]) -> [u8; 32],
{
    let canonical = encode()?;
    Ok(hash(b"ZcashTransparentPQ/wallet-proposal/v1\0", &canonical))
}

fn ids_equal(actual: &[u8; 32], approved: &[u8; 32]) -> bool {
    let mut index = 0;
    while index < 32 {
        if actual[index] != approved[index] {
            return false;
        }
        index += 1;
    }
    true
}

// FnMut keeps the continuation's state explicit in extraction. A rejection
// never calls it; acceptance calls it exactly once and preserves its result.
pub fn release<T, E, F>(
    actual: &[u8; 32],
    approved: &[u8; 32],
    mismatch: E,
    continuation: &mut F,
) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
{
    if !ids_equal(actual, approved) {
        return Err(mismatch);
    }
    continuation()
}
