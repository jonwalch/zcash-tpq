# Public conformance fixtures

These tools create deterministic public test data for `slh-dsa-b-128s-exp-v1`.
The fixture signer has its own Cargo workspace and lockfile.
Neither the node nor the wallet depends on it.
The operational wallet uses a separate in-process signer with fresh randomness.
Independent implementations calculate expected digests and signature results.

## Primitive service, version 1

The service accepts one JSON request on stdin and returns one response.
Each has a 32,768-byte limit.
Requests require `version: 1`, `contract: "slh-dsa-b-128s-exp-v1"`,
`public_fixture: true`, and `op`.
Unknown fields, malformed hex, and wrong lengths fail before cryptography.

| Operation | Inputs | Result |
| --- | --- | --- |
| `keygen` | A 48-byte hex `seed`: `SK.seed || SK.prf || PK.seed`, with 16 bytes each | A 32-byte public key and 64-byte secret key in hex, labeled public test material |
| `sign` | Hex `secret_key` (64 bytes), `message` (101 bytes), and `randomizer` (16 bytes) | Public key and 7,856-byte signature, after both upstream and the new verifier accept |

Signing uses empty context and external Pure framing once.
Errors contain no input or secret bytes.
The service has no profile, framing, context, repeat, or measurement switch.
A public-fixture label does not make real keys safe to use here.
Use only already-public test keys, including in live acceptance drivers.

Fixed input bounds keep the upstream short-message path within its buffers.
The PRF message input has 135 bytes. H_msg has 151 bytes.
Both fit its 384-byte buffer.
This does not establish safety for unrestricted upstream inputs.
The node uses a separate safe, bounded verifier.
Source, license, patch, and dependency changes require separate provenance records.

## Transaction artifacts

The [transaction schema](transaction-fixtures.md) specifies version 1 artifacts and the deterministic corpus.
An artifact records complete transaction bytes, supplied previous outputs in input order,
policy details, messages, signatures, expected outcomes, producer identities, and hashes.
These files contain no seeds, secret keys, or operational randomness.

| Resource | Maximum |
| --- | ---: |
| Complete encoded artifact | 16 MiB |
| Decoded transaction | 2,000,000 bytes |
| Transparent inputs / outputs | 32 / 64 |
| Each supplied previous-output script | 10,000 bytes |
| Each authorization | 131,072 bytes before canonical parsing |
| Each descriptor | 484 bytes |
| Participants / records per input | 15 / 15 |

These are test transport limits, not consensus parameters or wallet capacity promises.
Producers and readers check encoded and decoded limits separately.
Independent checks recalculate digests, commitments, and hashes.
Claimed fields cannot replace those calculations.
The corpus covers v5/v6, selected policies, budget boundaries, canonical encoding,
old-contract rejection, and mutations with identified failure stages.
Live and performance acceptance remain separate tests.
Agents must obtain user approval before these runs under [AGENTS.md](../../AGENTS.md).
