# Bounded public conformance fixtures

This test-only interface supplies deterministic public data for the
`slh-dsa-b-128s-exp-v1` contract. It is not the operational wallet signer.
The fixture signer has an isolated Cargo workspace and lockfile; neither the
node nor the wallet depends on it. Retain pinned upstream source, license and
patch inventories. Expected transaction digests and cryptographic comparisons
come from independent implementations.

## Primitive fixture service, version 1

Accept one JSON request on stdin, at most 32,768 encoded bytes. Reject unknown
fields, malformed hex and invalid lengths before key generation or signing.
Every request requires `version: 1`, `contract: "slh-dsa-b-128s-exp-v1"`,
`public_fixture: true`, and `op`.

* `op: "keygen"` requires a 48-byte hex `seed`. Interpret it as the three
  16-byte components `SK.seed || SK.prf || PK.seed`. Return the 32-byte public
  key and 64-byte secret key as hex, explicitly labeled public fixture material.
* `op: "sign"` requires hex `secret_key` (64 bytes), `message` (101 bytes),
  and `randomizer` (16 bytes). Context is always empty. Use external Pure
  framing once. Return the public key and 7,856-byte signature only after both
  pinned upstream verification and the new fixed-profile verifier accept it.

Responses are bounded to 32,768 bytes. Errors contain no input/secret bytes.
There is no profile, internal-framing, timing, repetition or arbitrary-context
switch. A `public_fixture` label does not authorize processing real wallet keys;
this service exists only for reproducible test material. The future disposable
live harness has a separate entropy and secret-lifetime boundary.

Retaining the pinned upstream short-message path is safe only under these fixed
input bounds: PRF message concatenation occupies 135 bytes and H_msg 151 bytes,
both below its 384-byte buffer. This does not justify using that implementation
as an unrestricted runtime API. The node verifier uses its separate safe,
bounded extraction. Record any dependency-only pin adaptation independently
from changes to algorithm source.

## Public transaction artifact limits

The transaction artifact schema is version 1 and uses the same contract label.
The concrete layout and deterministic corpus are specified in
[transaction fixtures](transaction-fixtures.md).
Its required contents are backend/source/hash identity, complete transaction
bytes, ordered input outpoints and trusted spent values/scripts, network/version/
branch/input index, descriptors and signer indices, exact messages and empty
contexts, public keys/signatures, expected outcome/rejection stage, and artifact
hashes. Never export seed, secret key or operational randomness fields.

| Resource | Maximum |
| --- | ---: |
| Complete encoded artifact | 16 MiB |
| Decoded transaction | 2,000,000 bytes |
| Transparent inputs / outputs | 32 / 64 |
| Each trusted previous-output script | 10,000 bytes |
| Each authorization | 131,072 bytes before canonical parsing |
| Each descriptor | 484 bytes |
| Participants / records per input | 15 / 15 |

These are bounded test transport limits, not new consensus parameters or a
wallet capacity guarantee. Producers and consumers check encoded and decoded
bounds independently. Independent checks recompute every digest, commitment and
artifact hash; claimed fields never substitute for those calculations. Include
valid v5/v6 cases, all selected policy shapes, exact/excess check budgets,
canonicality/old-contract rejection and mutations that identify their rejection
stage. Human-only live and resource acceptance remains separate.
