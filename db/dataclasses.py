import json
from dataclasses import dataclass
from typing import Optional


@dataclass
class DBNode:
    active: bool
    contract_id: str
    decommission_count: int
    earned_downtime_blocks: int
    fetched_block_height: int
    funded: bool
    is_liquidatable: bool
    is_removable: bool
    last_reward_block_height: int
    last_uptime_proof: int
    lokinet_version: dict | None
    operator_address: str
    operator_fee: int
    payable: bool
    pubkey_bls: str
    pubkey_ed25519: str
    public_ip: str | None
    pulse_votes: dict | None
    quorumnet_port: int | None
    registration_height: int
    registration_hf_version: str
    requested_unlock_height: int
    service_node_pubkey: str
    service_node_version: dict | None
    staking_requirement: int
    state_height: int
    storage_lmq_port: int | None
    storage_port: int | None
    storage_server_version: dict | None
    swarm: str
    swarm_id: str
    total_contributed: int
    # Not in db but added after select
    contributors: list | None

    def __post_init__(self):
        self.lokinet_version = json.loads(self.lokinet_version) if self.lokinet_version else None
        self.service_node_version = (
            json.loads(self.service_node_version) if self.service_node_version else None
        )
        self.storage_server_version = (
            json.loads(self.storage_server_version) if self.storage_server_version else None
        )
        self.pulse_votes = json.loads(self.pulse_votes) if self.pulse_votes else None


@dataclass
class DBContributionMain:
    address: str
    amount: int
    beneficiary: str | None
    contract_id: str
    fetched_block_height: int

    def __post_init__(self):
        # We don't need the contract_id or fetched_block_height fields when its a dict
        self.__dataclass_fields__ = {
            k: v
            for k, v in self.__dataclass_fields__.items()
            if k != "contract_id" and k != "fetched_block_height"
        }


@dataclass
class DBNetworkInfo:
    id: Optional[int]
    block_hash: str
    block_height: int
    block_timestamp: float
    hard_fork: int
    immutable_block_hash: str
    immutable_block_height: int
    max_stakers: int
    min_operator_contribution: int
    nettype: str
    pulse_target_timestamp: int
    staking_requirement: int
    version: str

    def __post_init__(self):
        # We don't need the id field when its a dict
        self.__dataclass_fields__ = {
            k: v for k, v in self.__dataclass_fields__.items() if k != "id"
        }


@dataclass
class DBContributionContract:
    address: str
    fee: int
    operator_address: str
    pubkey_bls: str
    service_node_pubkey: str
    service_node_signature: str
    status: int
    # Not in db but added after select
    contributors: list | None


@dataclass
class DBContributionContractContribution:
    address: str
    amount: int
    beneficiary_address: str
    contract_address: str
    reserved: int

    def __post_init__(self):
        # We don't need the contract_address field when its a dict
        self.__dataclass_fields__ = {
            k: v for k, v in self.__dataclass_fields__.items() if k != "contract_address"
        }


@dataclass
class SmartContractABI:
    name: str
    abi: dict
    bytecode: bytes
    deployed_bytecode: bytes

    def __post_init__(self):
        self.abi = json.loads(self.abi)

@dataclass
class ArbitrumEvent:
    block: int
    tx: str
    name: str
    args: str

    def __post_init__(self):
        self.args = json.loads(self.args)

@dataclass
class ArbitrumInfo:
    block: int
    timestamp: float
    balance_reward_rate_pool: int
    balance_service_node_rewards: int

@dataclass
class RewardsInfo:
    address: str
    rewards: int
