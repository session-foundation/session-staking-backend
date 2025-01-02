import logging
from typing import TypedDict
from oxen.omq import FutureJSON, omq_connection, RPCUsageTracker
from dataclasses import dataclass


class ServiceNodeContributor(TypedDict):
    address: str
    amount: int
    beneficiary: str
    locked_contributions: list[int]


class ServiceNode(TypedDict):
    active: bool
    contract_id: int
    # In separate table
    contributors: list[ServiceNodeContributor]
    decommission_count: int
    earned_downtime_blocks: int
    funded: bool
    is_liquidatable: bool
    is_removable: bool
    last_reward_block_height: int
    last_reward_transaction_index: int
    last_uptime_proof: int
    lokinet_version: list[int]
    operator_address: str
    operator_fee: int
    payable: bool
    portions_for_operator: int
    pubkey_bls: str
    pubkey_ed25519: str
    pubkey_x25519: str
    public_ip: str
    pulse_votes: dict[str, list[int]] | None
    quorumnet_port: int
    registration_height: int
    registration_hf_version: int
    requested_unlock_height: int
    service_node_pubkey: str
    service_node_version: list[int]
    staking_requirement: int
    state_height: int
    storage_lmq_port: int
    storage_port: int
    storage_server_version: list[int]
    swarm: str
    swarm_id: int
    total_contributed: int


@dataclass
class NetworkInfo:
    block_hash: str
    block_height: int
    hard_fork: int
    immutable_block_hash: str
    immutable_block_height: int
    max_stakers: int
    min_operator_contribution: int
    nettype: str
    pulse_target_timestamp: int
    staking_requirement: int
    version: str


class OxenRPC:
    def __init__(self, logger: logging, rpc_url: str, cache_seconds: float | None = None, usage_tracking: bool = False):
        self.log = logger
        self.rpc_url = rpc_url
        self.cache_seconds = cache_seconds
        self.usage_tracker = RPCUsageTracker(usage_tracking, self.log)

    def FutureJSON(self,endpoint: str, args: dict | None = None, cache_seconds: float | None = None, timeout: int | None = None):
        omq, oxend = omq_connection(self.rpc_url)
        return FutureJSON(
            omq=omq,
            oxend=oxend,
            endpoint=endpoint,
            args=args,
            cache_seconds=cache_seconds if cache_seconds is not None else self.cache_seconds,
            timeout=timeout,
            rpc_usage_tracker=self.usage_tracker,
        )

    def get_accrued_rewards(self) -> FutureJSON:
        return self.FutureJSON(
            "rpc.get_accrued_rewards",
            args={"addresses": []},
        )

    def bls_rewards_request(self, eth_address: str) -> FutureJSON:
        eth_address_for_rpc = eth_address.lower()
        if eth_address_for_rpc.startswith("0x"):
            eth_address_for_rpc = eth_address_for_rpc[2:]
        result = self.FutureJSON(
            "rpc.bls_rewards_request",
            args={"address": eth_address_for_rpc},
            timeout=20,
        )
        return result

    def bls_exit_liquidation_request(self, ed25519_pubkey: bytes, liquidate: bool) -> FutureJSON:
        return self.FutureJSON(
            "rpc.bls_exit_liquidation_request",
            args={"pubkey": ed25519_pubkey.hex(), "liquidate": liquidate},
        )

    def bls_exit_liquidation_list(self) -> FutureJSON:
        return self.FutureJSON(
            "rpc.bls_exit_liquidation_list",
        )

    def get_info(self) -> FutureJSON:
        return self.FutureJSON(
            "rpc.get_info",
        )

    def get_last_block_header(self) -> FutureJSON:
        return self.FutureJSON(
            "rpc.get_last_block_header",
            args={"fill_pow_hash": False, "get_tx_hashes": False},
        )

    def get_service_nodes(self) -> FutureJSON:
        return self.FutureJSON(
            "rpc.get_service_nodes",
            args={
                "all": True,
                # TODO: decide if we want to reduce the number of fields returned, this needs to match the database too
                # "fields": {
                #     x: True
                #     for x in (
                #         "service_node_pubkey",
                #         "requested_unlock_height",
                #         "last_reward_block_height",
                #         "active",
                #         "pubkey_bls",
                #         "funded",
                #         "earned_downtime_blocks",
                #         "service_node_version",
                #         "contributors",
                #         "total_contributed",
                #         "total_reserved",
                #         "staking_requirement",
                #         "portions_for_operator",
                #         "operator_address",
                #         "pubkey_ed25519",
                #         "last_uptime_proof",
                #         "state_height",
                #         "swarm_id",
                #         "is_removable",
                #         "is_liquidatable",
                #         "operator_fee"
                #     )
                # },
            },
        )

    def get_network_info_from_network(self):
        info = self.get_info().get()
        self.log.silly("get_network_info_from_network info: {}".format(info))

        return NetworkInfo(
            block_hash=info.get("top_block_hash"),
            block_height=info.get("height"),
            hard_fork=info.get("hard_fork"),
            immutable_block_hash=info.get("immutable_block_hash"),
            immutable_block_height=info.get("immutable_height"),
            max_stakers=info.get("max_contributors"),
            min_operator_contribution=info.get("min_operator_contribution"),
            nettype=info.get("nettype"),
            pulse_target_timestamp=info.get("pulse_target_timestamp"),
            staking_requirement=info.get("staking_requirement"),
            version=info.get("version"),
        )
