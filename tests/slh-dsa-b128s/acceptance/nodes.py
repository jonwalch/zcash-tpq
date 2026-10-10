"""Human-only local node lifecycle, adapted from research Node/History drivers."""
import contextlib
import json
from pathlib import Path
import socket
import subprocess
import urllib.error

import observations

from common import (AcceptanceError, Node, common_tip, require, sha256, wait_for,
                    write_json)

NU7_HEIGHT = 105
SLH_HEIGHT = 110
TX_LIMIT = 16
BLOCK_LIMIT = 64
SPEND_ACTIVATION_HEIGHTS = {"NU6.2": 1, "NU6.3": 104, "NU7": NU7_HEIGHT}


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def configuration(address, p2p, peer, state, miner, *, enabled=True, activation_heights=None):
    # A separate deposit window permits a nonzero Orchard note before NU6.3.
    # Keep the ordinary acceptance profile and the SLH activation gate intact.
    activations = f'"NU6.3" = 1, "NU7" = {NU7_HEIGHT}'
    if activation_heights is not None:
        require(type(activation_heights) is dict
                and activation_heights == SPEND_ACTIVATION_HEIGHTS
                and all(type(value) is int for value in activation_heights.values()),
                "unsupported_activation_profile")
        activations = ', '.join(f'"{name}" = {height}'
                                for name, height in SPEND_ACTIVATION_HEIGHTS.items())
    gate = (f"experimental_slh_dsa_b128s_activation_height = {SLH_HEIGHT}\n"
            f"experimental_slh_dsa_b128s_max_checks_per_transaction = {TX_LIMIT}\n"
            f"experimental_slh_dsa_b128s_max_checks_per_block = {BLOCK_LIMIT}\n") if enabled else ""
    return f'''[network]
network = "Regtest"
listen_addr = "127.0.0.1:{p2p}"
p2p_stack = "legacy"
cache_dir = false
initial_testnet_peers = {json.dumps([] if peer is None else [f"127.0.0.1:{peer}"])}

[network.testnet_parameters]
activation_heights = {{ {activations} }}
{gate}lockbox_disbursements = [{{ address = "t2RnBRiqrN1nW4ecZs1Fj3WWjNdnSs4kiX8", amount = 0 }}]

[state]
ephemeral = false
cache_dir = {json.dumps(str(state))}

[rpc]
listen_addr = "{address}"
enable_cookie_auth = false
parallel_cpu_threads = 2

[mempool]
debug_enable_at_height = 0

[mining]
internal_miner = false
miner_address = "{miner}"

[tracing]
filter = "info"
'''


class ManagedNode(Node):
    def __init__(self, binary, directory, label, miner, p2p, peer=None, *, observation_token=None,
                 activation_heights=None):
        self.directory = directory / label
        self.directory.mkdir(mode=0o700)
        self.config = self.directory / "node.toml"
        address = f"127.0.0.1:{port()}"
        self.config.write_text(configuration(address, p2p, peer, self.directory / "state", miner,
                                             activation_heights=activation_heights))
        self.observation_token = observation_token
        if observation_token is not None:
            observations.valid_token(observation_token)
            self.config.write_text(self.config.read_text().replace('filter = "info"',
                                  'filter = "info,slh_primitive=info"'))
        self.observation_captures = []
        self._observation_start = None
        self.binary = binary
        self.process = None
        self.log = None
        self.stops = []
        super().__init__(address, (self.directory / "rpc.jsonl").open("xb"))

    def start(self):
        require(self.process is None, "node_already_running")
        self.log = (self.directory / "node.log").open("ab")
        if self.observation_token is not None:
            try:
                self._observation_start = observations.begin(self.directory / "node.log", self.binary,
                                                            self.config, self.observation_token)
            except BaseException:
                self.log.close()
                raise
        self.process = subprocess.Popen([str(self.binary), "--config", str(self.config), "start"],
                                        stdout=self.log, stderr=subprocess.STDOUT,
                                        env=observations.environment(self.observation_token))
        def ready():
            require(self.process.poll() is None, "node_startup_failed")
            try:
                reply = self.response("getblockcount")
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                return False
            error = reply.get("error")
            # The RPC endpoint can open before genesis reaches the chain tip.
            # Retry only the pinned empty-state error, not arbitrary RPC failures.
            if (type(error) is dict and type(error.get("code")) is int
                    and error == {"code": -1, "message": "No blocks in state"}
                    and "result" not in reply):
                return False
            require(error is None and "result" in reply, "rpc_rejected_getblockcount")
            require(type(reply["result"]) is int and reply["result"] >= 0,
                    "node_startup_height")
            return True
        wait_for(ready, "node_startup_timeout", 60)

    def stop(self):
        if self.process is not None:
            pid = self.process.pid
            self.process.terminate()
            try:
                status = self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
                raise AcceptanceError("node_shutdown_timeout") from None
            finally:
                self.process = None
                self.log.close()
            self.stops.append(status)
            require(status == 0, "node_shutdown_failed")
            if self._observation_start is not None:
                capture = observations.finish(self._observation_start, self.directory / "node.log",
                                              self.binary, self.config, pid, status)
                name = f"observation-{len(self.observation_captures)}.json"
                path = write_json(self.directory / name, capture)
                self.observation_captures.append({"file": name, "sha256": sha256(path)})
                self._observation_start = None

    def close(self):
        try:
            self.stop()
        finally:
            self.events.close()


class Network:
    def __init__(self, binary, directory, miner, *, observation_token=None, activation_heights=None):
        first, second = port(), port()
        self.nodes = [ManagedNode(binary, directory, "node-a", miner, first, second,
                                  observation_token=observation_token, activation_heights=activation_heights),
                      ManagedNode(binary, directory, "node-b", miner, second, first,
                                  observation_token=observation_token, activation_heights=activation_heights)]
        self.a, self.b = self.nodes

    def __enter__(self):
        try:
            for node in self.nodes:
                node.start()
            wait_for(lambda: all(node.rpc("getpeerinfo") for node in self.nodes), "p2p_connection", 60)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        failures = []
        for node in reversed(self.nodes):
            try:
                node.close()
            except Exception as error:
                failures.append(error)
        if failures:
            raise failures[0]

    def mine(self, count=1):
        require(type(count) is int and 1 <= count <= 100, "mining_batch")
        hashes = self.a.rpc("generate", count)
        require(len(hashes) == count, "mining_count")
        wait_for(lambda: self.a.tip() == self.b.tip(), "mined_peer_tip", 60)
        return hashes

    def bootstrap(self):
        require(self.a.tip()[0] == self.b.tip()[0] == 0, "fresh_nodes_required")
        while self.a.tip()[0] < SLH_HEIGHT:
            self.mine(min(25, SLH_HEIGHT - self.a.tip()[0]))
        return common_tip(self.nodes)

    def restart(self):
        tip = common_tip(self.nodes)
        for node in self.nodes:
            node.stop()
        for node in self.nodes:
            node.start()
        require(common_tip(self.nodes) == tip, "restart_tip")
        return tip

    def metadata(self):
        return [{"config_sha256": sha256(node.config), "config": node.config.name,
                 "endpoint": node.address, "shutdown_exit_codes": node.stops,
                 **({"primitive_observation": {"token": node.observation_token,
                         "captures": node.observation_captures}}
                    if node.observation_token is not None else {})}
                for node in self.nodes]


def authenticate_coinbase(nodes, height, expected_script):
    tip = common_tip(nodes)
    require(tip["height"] - height + 1 >= 100, "coinbase_not_mature")
    block_hashes = [node.rpc("getblockhash", height) for node in nodes]
    require(block_hashes[0] == block_hashes[1], "funding_block_disagreement")
    transactions = [node.rpc("getblock", block_hashes[0], 1)["tx"][0] for node in nodes]
    require(transactions[0] == transactions[1], "coinbase_disagreement")
    parents = [node.rpc("getrawtransaction", transactions[0], 1) for node in nodes]
    require(parents[0]["hex"] == parents[1]["hex"] and parents[0]["vin"][0].get("coinbase")
            is not None, "funding_is_not_coinbase")
    matches = [output for output in parents[0]["vout"] if output["scriptPubKey"]["hex"] == expected_script]
    require(len(matches) == 1, "classical_miner_output")
    index = matches[0]["n"]
    observations = [node.rpc("gettxout", transactions[0], index, False) for node in nodes]
    require(all(output is not None and output["coinbase"] and output["confirmations"] >= 100
                and output["scriptPubKey"]["hex"] == expected_script for output in observations),
            "classical_outpoint_not_spendable")
    return {"parent_hex": parents[0]["hex"], "output_index": index,
            "txid": transactions[0], "height": height, "block_hash": block_hashes[0], "tip": tip}
