# Human acceptance adapters

Read the [acceptance runbook](../../../docs/slh-dsa-b128s/acceptance.md).
All builds and actual node, wallet, signing, recovery and terminal runs are
**human-only**. Importing these modules is inert. No historical result is relabeled
as SLH acceptance; receipts start incomplete and retain failed attempts.

The permitted offline suite is:

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/acceptance -p 'test_*.py' -v
```

It uses strict fake CLI/RPC/process boundaries and existing independent wallet
format calculations. It never launches a node, CLI terminal, signer, build,
container, proof generator or profiling workload. Install the same pinned Python
requirements as [wallet formats](../wallet/formats/requirements.txt).

Source mappings and file hashes are in [sources.json](sources.json); imported
code attribution is in [NOTICE](NOTICE). `fake_cli.py` is a test-only adapter,
and is never imported by a human live driver.

Additional prepared cases cover [transparent authorization and lifecycle](../../../docs/slh-dsa-b128s/transparent-controls.md)
and [hostile wallet history](../../../docs/slh-dsa-b128s/history-controls.md).
[Opt-in observation](../../../docs/slh-dsa-b128s/observations.md) records bounded
process/window primitive attempts without changing verification or retry rules.
Their focused mock tests do not establish live acceptance.
