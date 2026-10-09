use super::{review, InputRecord, Intent, Proposal};
use crate::{Entry, Error, Hex, WatchStore};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Local inventory effects, recomputed by each signer; never proposal metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ChangeReview {
    pub advancement: Option<ChangeAdvancement>,
    pub local_index: u32,
}

/// Explicit approval is required to retire the half-open range
/// [skipped_start, skipped_end), including entries for other ownership groups.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ChangeAdvancement {
    pub approval_id: Hex<32>,
    pub first_eligible_index: u32,
    pub skipped_end: u64,
    pub skipped_start: u64,
}

impl WatchStore {
    /// Shared by construction and independent approval. Inventory is validated
    /// in increasing local index order, which need not match a cosigner's order.
    pub(super) fn eligible_change(&self, inputs: &[InputRecord]) -> Result<Option<&Entry>, Error> {
        let ownership = review::group(&inputs.first().ok_or(Error::Policy)?.entry)?;
        for entry in &self.manifest().entries {
            if entry.role == 1
                && u64::from(entry.local(self.manifest().wallet_id)?.1.index)
                    >= self.state.payments.change_next
                && review::group(entry)? == ownership
                && !inputs
                    .iter()
                    .any(|input| input.entry.policy_hex == entry.policy_hex)
            {
                self.manifest()
                    .profile
                    .check_policy(&entry.suite_policy()?)?;
                return Ok(Some(entry));
            }
        }
        Ok(None)
    }

    pub(super) fn change_review(
        &self,
        proposal: &Proposal,
        intent: &Intent,
        reserved: bool,
    ) -> Result<Option<ChangeReview>, Error> {
        let Some(entry) = proposal
            .outputs
            .get(1)
            .and_then(|output| output.entry.as_ref())
        else {
            return Ok(None);
        };
        let local_index = entry.local(self.manifest().wallet_id)?.1.index;
        let cursor = self.state.payments.change_next;
        let advancement = if !reserved && u64::from(local_index) > cursor {
            let first = self
                .eligible_change(&proposal.inputs)?
                .ok_or(Error::Exhausted)?;
            let mut hash = Sha256::new();
            hash.update(b"ZcashTransparentPQ/change-advancement/v1\0");
            hash.update(self.manifest().fingerprint()?.0);
            hash.update(cursor.to_le_bytes());
            hash.update(proposal.id()?.0);
            hash.update(intent.to_json()?);
            Some(ChangeAdvancement {
                approval_id: Hex(hash.finalize().into()),
                first_eligible_index: first.local(self.manifest().wallet_id)?.1.index,
                skipped_end: u64::from(local_index),
                skipped_start: cursor,
            })
        } else {
            None
        };
        Ok(Some(ChangeReview {
            advancement,
            local_index,
        }))
    }
}
