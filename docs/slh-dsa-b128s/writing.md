# Documentation style and terms

The SLH documents use plain technical English guided by
[ASD-STE100, Issue 9](https://www.asd-ste100.org/assets/files/ASD-STE100_ISSUE9.pdf).
The target is “80% of the way”: clear and consistent, without strict dictionary
compliance or a claim of certified conformity.
This applies to the SLH guides, package and test READMEs, and root README.
Inherited Zakura documents and historical records retain their original wording.

## Writing rules

- Lead with what the feature or tool does.
- Prefer short sentences, active voice, and familiar words.
- Give each instruction one main action. Put required conditions first.
- Define specialist terms where readers first need them.
- Use one term consistently for each concept.
- Keep exact commands, identifiers, protocol bytes, source pins, and license text.
- Distinguish implemented features, completed tests, and tests that still need execution.
- Link to the main explanation instead of repeating it across guides.
- Use tables for limits or comparisons. Use lists for steps or parallel items.

Technical specifications can retain precise domain terms and longer sentences
when those make the requirement clearer.
An edit must preserve conditions, limits, exceptions, and uncertainty.
Historical test receipts apply only to their recorded inputs.
A documentation edit cannot extend their results to a later build.

## Common terms

| Term | Meaning in this repository |
| --- | --- |
| Transparent funds | Funds whose transaction amounts and output scripts are public. |
| PQ | Post-quantum: cryptography intended to resist attacks by quantum computers. |
| SLH | The experimental SLH-DSA-B-128s signature scheme added here. |
| Regtest | A local test network with controlled block production and activation settings. |
| Multisig, m-of-n | A policy that requires signatures from m of its n participants. |
| UTXO | An unspent transaction output. A trusted node must authenticate it before wallet use. |
| Mempool | Transactions a node holds for possible inclusion in a block. |
| Reorg | Replacement of part of the active chain by another branch. |
| Canonical encoding | The one permitted byte representation of a value under the specified format. |
| Partial | One signer's signature and identifying fields for one approved payment input. |
| Allocator | The watch store allowed to issue backed-up addresses and reserve payment inputs. |
| Monitor | A watch-only store that cannot issue addresses, sign, or submit payments. |
| Fingerprint | A hash that identifies exact data. It needs a separate trusted source for authentication. |
| Fixture | Prepared test data. Fixture keys in this repository are public and unsuitable for real funds. |
| Oracle | A separate implementation that calculates expected test results. |
| Receipt | A record of a test or build, including its inputs, identities, and outcome. |
| Anchor | A shielded tree root used to establish a note's membership for a spend. |
| Nullifier | A public identifier that prevents a shielded note from being spent twice. |
