# Clean product source guard

See the [packaging guide](../../../docs/slh-dsa-b128s/packaging.md) for the audit,
ledger maintenance, isolated clone procedure and publication boundary.

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/release-content -p 'test_*.py' -v
python3 tests/slh-dsa-b128s/release-content/check.py --packages
```

Python 3.11+, Git and the pinned Cargo toolchain are required; no third-party
Python library or research checkout is needed. Checks use temporary miniature Git
repositories and real archive inspection, or mocked bounded publication inputs.
No daemon, signer, terminal, build, network fetch, benchmark or publication runs.
Source attribution is in [NOTICE](NOTICE).
