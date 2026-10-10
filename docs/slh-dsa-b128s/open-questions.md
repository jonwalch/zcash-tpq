# Open questions

This page tracks unresolved choices for the SLH extension.
The [protocol](protocol.md) and component guides describe the implemented rules.
The [validation guide](validation.md) tracks evidence and tests that still need execution.

## F1: Fees beyond Regtest

Status: Open.

Which fee rate should apply beyond Regtest?
Should SLH have a separate fee adjustment for its resource costs?

The implementation uses Zakura's 400-zatoshi rate and ZIP-317 action counts.
It applies no SLH fee discount or surcharge.
The [fee policy discussion](relay-mining.md#fee-policy-discussion) compares the ZIPs,
shows the effect of SLH signature sizes, and lists the required decisions.
Those decisions need cost evidence and a review of wallet and node compatibility.
The current Regtest fees do not establish a production fee policy.

When a question is resolved, record the decision and its reason.
Update the affected guide and mark the question as resolved here.
