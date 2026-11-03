# TPQ preview starter inputs

Use these files with the matching [ZDN walkthrough](../zdn.md). They contain no
keys, funding authority, approved hashes or working AWS defaults.

- Copy `env.sh.in` to `$WORK/env.sh` (mode 0600) and load it in every terminal.
  It lists each walkthrough value and where it comes from. Later steps append
  captured values. It holds no passwords, keys, cookies or credentials.
- The walkthrough fills `external.yaml` from that environment with `sed`.
  Review the result; no `REPLACE` value may remain.
  Its revision is the distributed source repository's Git revision, not necessarily
  the original TPQ commit. The source map must explain that relationship.
- `core-trust.json.in` is the exact `CoreTrust` shape. Zero byte counts and
  `REPLACE` hashes deliberately refuse. Fill it only after independent review.
- `payment-intent.json.in` is an editable input, not canonical wallet JSON.
  Generate a compact, sorted, no-newline file with the guide's `jq` command.
  Amount and fee ceiling are examples, not automatic approval or a fee quote.
- The five action files are typed ZDN control inputs. They do not authorize
  execution. `produce-102.json` is valid only when the stable current tip is 101.
  New controls require new saved IDs. Recovery uses the original ID, not a copy
  of an action file.

The example cadence is 3600 seconds so the operator can stop scheduled production
and use saved bounded controls. It is not a guarantee that no scheduled block
will race an observation. Check the stable tip after stopping. The explicit
height-121 and six-hour (21600-second, the controller maximum) production
lifetime ceilings start at `devnet up` and do not renew on restart. They
are not defaults, a wall-clock kill switch or a spending cap.

## Packaging

Package this directory unchanged under `docs/slh-dsa-b128s/zdn-preview/` with
`zdn.md`, `protocol.md`, `writing.md`, `devnet.md`, `devnets.md`, `cli.md`,
`wallet.md` and `recovery.md` in their existing relative locations. Include the
matching ZDN `docs/` references used by the distribution's ZDN entry guide.
An alias `START-TPQ.md` placed beside `zdn.md` keeps its guide links valid. If the
separate instructions asset is renamed to `START-TPQ.md` at the extraction root,
adapt its relative links to the retained documentation tree during packaging;
do not present broken links as a complete installation. The source archives remain
the reference for optional source/test links. Pin the starter archive and instructions in the distribution
index. Do not add generated public seeds, `funder.json`, wallet stores, private
receipts or R8 operational files to this static starter archive.
