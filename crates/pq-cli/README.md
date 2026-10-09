# Experimental SLH wallet CLI

`pq-wallet` manages SLH wallets on Regtest.
It reuses the wallet's command flows and private-terminal password handling.
The `experimental-slh-dsa-b128s` feature enables wallet operations.
Without it, the CLI offers help and has no normal or build dependencies.

The [command guide](../../docs/slh-dsa-b128s/cli.md) explains use.
The [wallet contract](../../docs/slh-dsa-b128s/wallet.md) specifies formats and limits.
[Source mappings](../pq-wallet/CLI_RPC_PROVENANCE.json) record attribution.
Parser and mocked loopback tests do not establish live node or terminal acceptance.
