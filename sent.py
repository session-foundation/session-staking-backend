#!/usr/bin/env python3
from time import perf_counter

import asyncio
from concurrent.futures import ThreadPoolExecutor
import uuid

import flask
import string
import time
import oxenc
import sqlite3
import re
import nacl.hash
import nacl.bindings as sodium
import eth_utils
import subprocess
import config
import datetime

from itertools        import chain
from eth_typing       import ChecksumAddress
from typing           import TypedDict, Callable, Any, Union
from functools        import partial
from werkzeug.routing import BaseConverter
from nacl.signing     import VerifyKey
from omq              import FutureJSON, omq_connection
from timer            import timer

from contracts.reward_rate_pool                  import RewardRatePoolInterface
from contracts.service_node_contribution         import ContributorContractInterface
from contracts.service_node_contribution_factory import ServiceNodeContributionFactory
from contracts.service_node_rewards              import ServiceNodeRewardsInterface, ServiceNodeRewardsRecipient

TOKEN_NAME = "SENT"

class WalletInfo():
    def __init__(self):
        self.rewards          = 0 # Atomic SENT
        self.contract_rewards = 0
        self.contract_claimed = 0

def oxen_rpc_get_accrued_rewards(omq, oxend) -> FutureJSON:
    result = FutureJSON(omq, oxend, 'rpc.get_accrued_rewards', args={'addresses': []})
    return result

def oxen_rpc_bls_rewards_request(omq, oxend, eth_address: str) -> FutureJSON:
    eth_address_for_rpc = eth_address.lower()
    if eth_address_for_rpc.startswith("0x"):
        eth_address_for_rpc = eth_address_for_rpc[2:]
    result = FutureJSON(omq, oxend, 'rpc.bls_rewards_request', args={'address': eth_address_for_rpc})
    return result

def oxen_rpc_bls_exit_liquidation(omq, oxend, ed25519_pubkey: bytes, liquidate: bool) -> FutureJSON:
    return FutureJSON(omq, oxend, 'rpc.bls_exit_liquidation_request', args={'pubkey': ed25519_pubkey.hex(), 'liquidate': liquidate})

def get_oxen_rpc_bls_exit_liquidation_list(omq, oxend):
    return FutureJSON(omq, oxend, 'rpc.bls_exit_liquidation_list')

class App(flask.Flask):
    def __init__(self):
        super().__init__(__name__)
        self.logger.setLevel(config.backend.log_level)

        self.service_node_rewards              = ServiceNodeRewardsInterface(config.backend.provider_url,    config.backend.sn_rewards_addr)
        self.reward_rate_pool                  = RewardRatePoolInterface(config.backend.provider_url,        config.backend.reward_rate_pool_addr)
        self.service_node_contribution_factory = ServiceNodeContributionFactory(config.backend.provider_url, config.backend.sn_contrib_factory_addr)
        self.service_node_contribution         = ContributorContractInterface(config.backend.provider_url)

        self.bls_pubkey_to_contract_id_map: dict[str, int]      = {} # (BLS public key -> contract_id)

        self.wallet_to_sn_map: dict[ChecksumAddress, set[int]]  = {} # (0x wallet address -> Set of contract_id's of stakes they are contributors to)
        self.contract_id_to_sn_map: dict[int, dict]             = {} # (contract_id -> Oxen RPC get_service_nodes result (augmented w/ extra metadata like SN contract ID))

        self.wallet_to_exitable_sn_map: dict[ChecksumAddress, set[int]]         = {} # (0x wallet address -> Set of contract_id's of SN's they can liquidate/exit)
        self.contract_id_to_exitable_sn_map: dict[int, dict]                    = {} # (contract_id -> SNInfo)

        self.tmp_db_trigger_wallet_addresses: set[ChecksumAddress]              = set() # Wallet addresses that have triggered a db get between scheduled times
        self.tracked_wallet_addresses: set[ChecksumAddress]                     = set() # Tracked wallet addresses to fetch data from the db for
        self.wallet_to_historical_stakes_map: dict[ChecksumAddress, set[int]]   = {} # (0x wallet address -> Set of contract_ids)
        self.contract_id_to_historical_stakes_map: dict[int, Stake]             = {} # (contract_id -> Stake Info)


        self.contributors                      = {}

        self.contracts_stale_timestamp         = 0
        self.contracts                         = None

        self.wallet_map                        = {} # (Binary ETH wallet address -> WalletInfo)
        git_rev                                = subprocess.run(["git", "rev-parse", "--short=9", "HEAD"], stdout=subprocess.PIPE, text=True)
        self.git_rev                           = git_rev.stdout.strip() if git_rev.returncode == 0 else "(unknown)"

        sql = sqlite3.connect(config.backend.sqlite_db)
        cursor = sql.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS registrations (
                id INTEGER PRIMARY KEY NOT NULL,
                pubkey_ed25519 BLOB NOT NULL,
                pubkey_bls BLOB NOT NULL,
                sig_ed25519 BLOB NOT NULL,
                sig_bls BLOB NOT NULL,
                operator BLOB NOT NULL,
                contract BLOB,
                timestamp FLOAT NOT NULL DEFAULT ((julianday('now') - 2440587.5)*86400.0), /* unix epoch */

                CHECK(length(pubkey_ed25519) == 32),
                CHECK(length(pubkey_bls) == 64),
                CHECK(length(sig_ed25519) == 64),
                CHECK(length(sig_bls) == 128),
                CHECK(length(operator) == 20),
                CHECK(contract IS NULL OR length(contract) == 20)
            )
            """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS registrations_operator_idx ON registrations(operator);
        """)

        cursor.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS registration_pk_multi_idx ON registrations(pubkey_ed25519, contract IS NULL);
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS contribution_contracts (
                contract_address BLOB PRIMARY KEY NOT NULL,
                pubkey_ed25519 BLOB NOT NULL,
                pubkey_bls BLOB NOT NULL,
                sig_ed25519 BLOB NOT NULL,
                operator_address TEXT NOT NULL,
                fee INTEGER NOT NULL,
                status INTEGER NOT NULL,
                total_contributions INTEGER NOT NULL DEFAULT 0,
                
                timestamp FLOAT NOT NULL DEFAULT ((julianday('now') - 2440587.5)*86400.0), /* unix epoch */

                CHECK(length(contract_address) == 20)
            );
        """)

        cursor.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS contribution_contract_address_idx ON contribution_contracts(contract_address);
         """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS contribution_contracts_contributions (
                contract_address BLOB NOT NULL,
                address BLOB NOT NULL,
                beneficiary_address BLOB NOT NULL,
                amount INTEGER NOT NULL,
                reserved INTEGER,
                
                CHECK(length(address) == 20),
                
                FOREIGN KEY (contract_address) REFERENCES contribution_contracts(contract_address),
                PRIMARY KEY (contract_address, address)
            );
        """)

        cursor.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_contribution_contracts_contributions_contract_address_address ON contribution_contracts_contributions(contract_address, address);
            """)

        cursor.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_contribution_contracts_contributions_contract_address_address_amount ON contribution_contracts_contributions(contract_address, address, amount);
                """)


        cursor.execute("""
            CREATE TABLE IF NOT EXISTS stakes (
                id INTEGER PRIMARY KEY NOT NULL, /* Contract ID */
                last_updated INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),

                pubkey_bls BLOB NOT NULL,
                deregistration_unlock_height INTEGER,
                earned_downtime_blocks INTEGER,
                last_reward_block_height INTEGER,
                last_uptime_proof INTEGER,
                operator_address BLOB NOT NULL,
                operator_fee INTEGER,
                requested_unlock_height INTEGER,
                service_node_pubkey BLOB NOT NULL,
                state TEXT NOT NULL
                
                CHECK(length(operator_address) == 20)
                
            )
            """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS stake_contributions (
                contract_id INTEGER NOT NULL,
                address BLOB NOT NULL,
                amount INTEGER NOT NULL,
                reserved INTEGER,
                
                CHECK(length(address) == 20),
                
                FOREIGN KEY (contract_id) REFERENCES stakes(id),
                PRIMARY KEY (contract_id, address)
            );
        """)

        cursor.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_stake_contributions_contract_id_address ON stake_contributions(contract_id, address);
            """)

        cursor.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_stake_contributions_contract_id_address_amount ON stake_contributions(contract_id, address, amount);
            """)


        cursor.close()
        sql.close()


app = App()

def get_sql():
    if "db" not in flask.g:
        flask.g.sql = sqlite3.connect(config.backend.sqlite_db)
    return flask.g.sql

def date_now_str() -> str:
    result = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    return result

# Validates that input is 64 hex bytes and converts it to 32 bytes.
class Hex64Converter(BaseConverter):
    def __init__(self, url_map):
        super().__init__(url_map)
        self.regex = "[0-9a-fA-F]{64}"

    def to_python(self, value):
        return bytes.fromhex(value)

    def to_url(self, value):
        return value.hex()


eth_regex = "0x[0-9a-fA-F]{40}"
class EthConverter(BaseConverter):
    def __init__(self, url_map):
        super().__init__(url_map)
        self.regex = eth_regex


class OxenConverter(BaseConverter):
    def __init__(self, url_map):
        super().__init__(url_map)
        self.regex = config.backend.oxen_wallet_regex


class OxenEthConverter(BaseConverter):
    def __init__(self, url_map):
        super().__init__(url_map)
        self.regex = f"{eth_regex}|{config.backend.oxen_wallet_regex}"


app.url_map.converters["hex64"]         = Hex64Converter
app.url_map.converters["eth_wallet"]    = EthConverter
app.url_map.converters["oxen_wallet"]   = OxenConverter
app.url_map.converters["either_wallet"] = OxenEthConverter


def get_sns_future(omq, oxend) -> FutureJSON:
    return FutureJSON(
        omq,
        oxend,
        "rpc.get_service_nodes",
        args={
            "all": False,
            "fields": {
                x: True
                for x in (
                    "service_node_pubkey",
                    "requested_unlock_height",
                    "last_reward_block_height",
                    "active",
                    "pubkey_bls",
                    "funded",
                    "earned_downtime_blocks",
                    "service_node_version",
                    "contributors",
                    "total_contributed",
                    "total_reserved",
                    "staking_requirement",
                    "portions_for_operator",
                    "operator_address",
                    "pubkey_ed25519",
                    "last_uptime_proof",
                    "state_height",
                    "swarm_id",
                    "is_removable",
                    "is_liquidatable",
                    "operator_fee"
                )
            },
        },
    )

def get_sns(sns_future, info_future):
    info = info_future.get()
    awaiting_sns, active_sns, inactive_sns = [], [], []
    sn_states = sns_future.get()
    sn_states = (
        sn_states["service_node_states"] if "service_node_states" in sn_states else []
    )
    for sn in sn_states:
        sn["contribution_open"] = sn["staking_requirement"] - sn["total_reserved"]
        sn["contribution_required"] = (
            sn["staking_requirement"] - sn["total_contributed"]
        )
        sn["num_contributions"] = sum(
            len(x["locked_contributions"])
            for x in sn["contributors"]
            if "locked_contributions" in x
        )

        if sn["active"]:
            active_sns.append(sn)
        elif sn["funded"]:
            sn["decomm_blocks_remaining"] = max(sn["earned_downtime_blocks"], 0)
            sn["decomm_blocks"] = info["height"] - sn["state_height"]
            inactive_sns.append(sn)
        else:
            awaiting_sns.append(sn)
    return awaiting_sns, active_sns, inactive_sns


def hexify(container):
    """
    Takes a dict or list and mutates it to change any `bytes` values in it to str hex representation
    of the bytes, recursively.
    """
    if isinstance(container, dict):
        it = container.items()
    elif isinstance(container, list):
        it = enumerate(container)
    else:
        return

    for i, v in it:
        if isinstance(v, bytes):
            container[i] = v.hex()
        else:
            hexify(v)


def get_timers_hours(network_type: str):
    match network_type:
        case 'testnet' | 'stagenet' | 'devnet' | 'localdev' | 'fakechain':
            return {
                'deregistration_lock_duration_hours': 48,
                'unlock_duration_hours': 24,
            }
        case 'mainnet':
            return {
                'deregistration_lock_duration_hours': 30 * 24,
                'unlock_duration_hours': 15 * 24,
            }
        case _:
            raise ValueError(f"Unknown network type {network_type}")


@app.route("/timers/<network_type>")
def fetch_network_timers(network_type: str = None):
    if network_type is None:
        return json_response(get_timers_hours(get_info().get('nettype')))
    else:
        return json_response(get_timers_hours(network_type))


# Target block time in seconds
TARGET_BLOCK_TIME = 120


def blocks_in(seconds: int):
    """
    Mimics the behavior of the oxend `blocks_in` function.
    """
    return int(seconds / TARGET_BLOCK_TIME)


def get_info() -> dict:
    omq, oxend                     = omq_connection()
    info: dict | None              = FutureJSON(omq, oxend, "rpc.get_info").get()
    blk_header_result: dict | None = FutureJSON(omq, oxend, 'rpc.get_last_block_header', args={'fill_pow_hash': False, 'get_tx_hashes': False }).get()

    result: dict                        = {}
    result['nettype']                   = info['nettype']
    result['hard_fork']                 = info['hard_fork']
    result['version']                   = info['version']
    result['block_hash']                = info['top_block_hash']
    result['staking_requirement']       = info['staking_requirement']
    result['max_stakers']               = info['max_contributors']
    result['min_operator_contribution'] = info['min_operator_contribution']

    blk_header                          = blk_header_result['block_header']
    result['block_timestamp']           = blk_header['timestamp']
    result['block_height']              = blk_header['height']
    result['block_hash']                = blk_header['hash']
    return result


def json_response(vals):
    """
    Takes a dict, adds some general info fields to it, and jsonifies it for a flask route function
    return value.  The dict gets passed through `hexify` first to convert any bytes values to hex.
    """

    hexify(vals)

    return flask.jsonify({**vals, "network": get_info(), "t": time.time()})


def get_frequently_update_contract_details(address: str):
    try:
        contract_interface = app.service_node_contribution.get_contract_instance(address)

        contributions = contract_interface.get_contributions()
        status = contract_interface.status()

        total_contributions = 0
        for contribution in contributions:
            amount = contribution.get('amount')
            total_contributions += amount

        return address, status, contributions, total_contributions
    except Exception as e:
        app.logger.error("Error occurred while updating contract info: {}".format(e))
        return None


def get_base_contract_details(address: str):
    contract_interface = app.service_node_contribution.get_contract_instance(address)
    # Fetch statuses and other details
    # TODO: this does 3 network requests one after the other, we need to improve this
    operator = contract_interface.get_operator()
    pubkey_bls = contract_interface.get_bls_pubkey()
    service_node_params = contract_interface.get_service_node_params()
    service_node_pubkey = service_node_params.get('serviceNodePubkey')
    service_node_signature = service_node_params.get('serviceNodeSignature')
    fee = service_node_params.get('fee')

    # TODO: this does 2 network requests one after the other, we need to improve this
    _, status, contributions, total_contributions = get_frequently_update_contract_details(address)

    return address, operator, pubkey_bls, service_node_pubkey, service_node_signature, fee, status, contributions, total_contributions


get_frequently_update_contract_details_loop = asyncio.get_event_loop()

async def update_contributor_contracts(addresses):
    results = []
    with ThreadPoolExecutor(max_workers=config.backend.thread_pool_max_workers) as executor:
        get_frequently_update_contract_details_loop = asyncio.get_event_loop()
        futures = [
            get_frequently_update_contract_details_loop.run_in_executor(
                executor,
                get_frequently_update_contract_details,
                address
            ) for address in addresses
        ]
        for future in asyncio.as_completed(futures):
            try:
                # This will raise an exception if the thread raised an exception
                result = await future
                results.append(result)

            except Exception as e:
                app.logger.error("Error occurred in thread: {}".format(e))
    return results


get_base_contract_details_loop = asyncio.get_event_loop()


async def get_base_contract_details_contracts(addresses):
    results = []
    with ThreadPoolExecutor(max_workers=config.backend.thread_pool_max_workers) as executor:
        get_base_contract_details_loop = asyncio.get_event_loop()
        futures = [
            get_base_contract_details_loop.run_in_executor(
                executor,
                get_base_contract_details,
                address
            ) for address in addresses
        ]
        for future in asyncio.as_completed(futures):
            try:
                # This will raise an exception if the thread raised an exception
                result = await future
                if result is None:
                    continue
                results.append(result)
            except Exception as e:
                app.logger.error("Error occurred in thread: {}".format(e))
    return results


@timer(30)
def process_new_contribution_contracts(signum):
    app.logger.info("{} Process new contribution contracts start".format(date_now_str()))
    perf_start = perf_counter()

    new_contracts = app.service_node_contribution_factory.get_latest_contribution_contract_events()

    app.logger.debug('Found {} new contract events'.format(len(new_contracts)))

    addresses = []
    for event in new_contracts:
        contract_address = event.args.contributorContract
        if contract_address is None:
            continue
        addresses.append(contract_address)

    results = get_base_contract_details_loop.run_until_complete(get_base_contract_details_contracts(addresses))

    with app.app_context(), get_sql() as sql:
        cursor = sql.cursor()
        for details in results:
            if details is None:
                app.logger.warning("No details for new contract")
                continue

            address, operator, pubkey_bls, service_node_pubkey, service_node_signature, fee, status, contributions, total_contributions = details
            contract_address_bytes = address_to_bytes(address)

            cursor.execute(
                """
                INSERT INTO contribution_contracts (contract_address, pubkey_ed25519, pubkey_bls, sig_ed25519, operator_address, fee, status, total_contributions) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (contract_address) DO NOTHING
                """,
                (contract_address_bytes, service_node_pubkey, pubkey_bls, service_node_signature, operator, fee, status,
                 total_contributions)
            )

            for contributor in contributions:
                stake_address = address_to_bytes(contributor.get('address'))
                beneficiary_address = address_to_bytes(contributor.get('beneficiary'))
                amount = contributor.get('amount')

                cursor.execute(
                    """
                    INSERT INTO contribution_contracts_contributions (contract_address, address, beneficiary_address, amount) VALUES (?, ?, ?, ?)
                    """,
                    (contract_address_bytes, stake_address, beneficiary_address, amount)
                )

        sql.commit()

    perf_end = perf_counter()
    perf_diff = perf_end - perf_start

    app.logger.info("{} Process new contribution contracts end, took: {}s".format(date_now_str(), perf_diff))


# // Track the status of the multi-contribution contract. At any point in the
# // contract's lifetime, `reset` can be invoked to set the contract back to
# // `WaitForOperatorContrib`.
# enum Status {
#     // Contract is initialised w/ no contributions. Call `contributeFunds`
#     // to transition into `OpenForPublicContrib`
#     WaitForOperatorContrib, # 0
#
#     // Contract has been initially funded by operator. Public and reserved
#     // contributors can now call `contributeFunds`. When the contract is
#     // collaterialised with exactly the staking requirement, the contract
#     // transitions into `WaitForFinalized` state.
#     OpenForPublicContrib, # 1
#
#     // Operator must invoke `finalizeNode` to transfer the tokens and the
#     // node registration details to the `stakingRewardsContract` to
#     // transition to `Finalized` state.
#     WaitForFinalized, # 2
#
#     // Contract interactions are blocked until `reset` is called.
#     Finalized # 3
# }

def parse_contributor_contract_status(status: int):
    if status == 0 or status == 1:
        return "awaiting_contributors"
    elif status == 2:
        return "finalizing"
    elif status == 3:
        return "finalized"
    else:
        raise ValueError(f"Invalid contributor contract status: {status}")


CONTRACT_STATUS_UPDATE_TIME = 30


@timer(CONTRACT_STATUS_UPDATE_TIME)
def update_contract_details(signum):
    app.logger.info("{} Update Contract Statuses Start".format(date_now_str()))
    perf_start = perf_counter()

    addresses = []
    with app.app_context(), get_sql() as sql:
        cursor = sql.cursor()
        cursor.execute("SELECT contract_address FROM contribution_contracts")
        for address, in cursor:
            addresses.append(eth_format(address))

    result = get_frequently_update_contract_details_loop.run_until_complete(update_contributor_contracts(addresses))

    with app.app_context(), get_sql() as sql:
        cursor = sql.cursor()
        for details in result:
            if details is None:
                app.logger.warning("No details for contract")
                continue
            address, status, contributions, total_contributions = details
            contract_address_bytes = address_to_bytes(address)
            cursor.execute(
                """
                UPDATE contribution_contracts SET status = ?, total_contributions=? WHERE contract_address = ?
                """,
                (status, total_contributions, contract_address_bytes)
            )

            for contributor in contributions:
                stake_address = address_to_bytes(contributor.get('address'))
                beneficiary_address = address_to_bytes(contributor.get('beneficiary'))
                amount = contributor.get('amount')

                cursor.execute(
                    """
                    INSERT OR REPLACE INTO contribution_contracts_contributions (contract_address, address, beneficiary_address, amount) VALUES (?, ?, ?, ?)
                    """,
                    (contract_address_bytes, stake_address, beneficiary_address, amount)
                )

        sql.commit()

    perf_end = perf_counter()
    perf_diff = perf_end - perf_start

    if perf_diff > CONTRACT_STATUS_UPDATE_TIME:
        app.logger.warning("{} Update Contract Statuses Finish, took: {} seconds".format(date_now_str(), perf_diff))
    else:
        app.logger.info("{} Update Contract Statuses Finish, took: {} seconds".format(date_now_str(), perf_diff))


def get_contribution_contracts():
    if time.time() < app.contracts_stale_timestamp and app.contracts is not None:
        return app.contracts

    contracts = {}
    with app.app_context(), get_sql() as sql:
        cursor = sql.cursor()
        cursor.execute(
            "SELECT contract_address, pubkey_ed25519, pubkey_bls, sig_ed25519, operator_address, fee, status, total_contributions FROM contribution_contracts")
        for contract_address, service_node_pubkey, pubkey_bls, service_node_signature, operator, fee, status, total_contributions in cursor:
            contracts[contract_address] = {
                "service_node_pubkey": service_node_pubkey,
                "pubkey_bls": pubkey_bls,
                "service_node_signature": service_node_signature,
                "operator": operator,
                "fee": fee,
                "contract_state": parse_contributor_contract_status(status),
                "total_contributions": total_contributions
            }

        cursor.execute(
            "SELECT contract_address, address, beneficiary_address, amount FROM contribution_contracts_contributions")
        for contract_address, address, beneficiary_address, amount in cursor:
            if contract_address not in contracts:
                continue
            contracts[contract_address].setdefault("contributors", []).append({
                "address": address,
                "beneficiary": beneficiary_address,
                "amount": amount
            })

    app.contracts = contracts
    app.contracts_stale_timestamp = time.time() + config.backend.stale_time_seconds
    return app.contracts


@timer(10)
def fetch_service_nodes(signum):
    app.logger.info("{} Update SN Start".format(date_now_str()))
    omq, oxend            = omq_connection()

    # Generate new state
    sn_info_list      = get_sns_future(omq, oxend).get()["service_node_states"]
    wallet_to_sn_map  = {}
    sn_map            = {}

    if len(app.bls_pubkey_to_contract_id_map) == 0:
        app.logger.warning("{} bls_pubkey_to_contract_id_map is empty, fetching contract ids".format(date_now_str()))
        update_service_node_contract_ids(None)

    for sn_info in sn_info_list:
        # Add the SN contract ID to the sn_info dict
        pubkey_bls = sn_info.get('pubkey_bls')
        if pubkey_bls is None:
            app.logger.warning(f"pubkey_bls is None for sn_info SN: {sn_info}")
            continue
        contract_id = app.bls_pubkey_to_contract_id_map.get(pubkey_bls)
        if contract_id is None:
            app.logger.warning(f"Contract ID not found for sn_info SN with BLS pubkey: {pubkey_bls}")
            continue

        sn_info["contract_id"] = contract_id
        requested_unlock_height = sn_info.get('requested_unlock_height')
        sn_info['requested_unlock_height'] = requested_unlock_height if requested_unlock_height != 0 else None
        sn_map[contract_id] = sn_info

        contributors = {c["address"]: c["amount"] for c in sn_info["contributors"]}
        # Creating (wallet -> [SN's the wallet owns]) table
        for wallet_key in contributors.keys():
            # TODO: Validate we want to allow wallet_key to not go through eth_format if len == 40
            formatted_wallet_key = eth_format(wallet_key) if len(wallet_key) == 40 else wallet_key

            if formatted_wallet_key is None:
                app.logger.warning(f"Wallet key is None for sn_info SN: {sn_info}")
                continue

            wallet_to_sn_map.setdefault(formatted_wallet_key, []).append(contract_id)

    # Apply the new state if there are any
    if len(sn_map) > 0:
        app.logger.debug(f"Adding {len(sn_map)} service node info to the contract_id_to_sn_map")
        app.contract_id_to_sn_map     = sn_map

        app.logger.debug(f"Adding {len(wallet_to_sn_map)} wallet to service node map")
        app.wallet_to_sn_map          = wallet_to_sn_map

    # Get list of SNs that can be liquidated/exited
    exit_liquidation_list_json = get_oxen_rpc_bls_exit_liquidation_list(omq, oxend).get()

    exitable_sns = {}
    wallet_to_exitable_sn_map = {}

    if exit_liquidation_list_json is not None:
        net_info = get_info()
        net_type = net_info.get('nettype')
        timers = get_timers_hours(net_type)

        for entry in exit_liquidation_list_json:
            sn_info = entry.get('info')

            pubkey_bls = sn_info.get('bls_public_key')
            if pubkey_bls is None:
                app.logger.warning(f"bls_public_key is None for exit_liquidation_list_json SN: {sn_info}")
                continue

            contract_id = app.bls_pubkey_to_contract_id_map.get(pubkey_bls)
            if contract_id is None:
                # If there is no contract ID it means this node has exited the smart contract and this event is being
                #  confirmed by oxend. This is the last state we'll get for this node from oxend.
                # TODO: look at implementing some logic to add the node data to a dict that checks to make sure the db
                #  is properly updated with the final data we'll receive from oxend about this node.
                app.logger.warning(f"Contract ID not found for exit_liquidation_list_json SN with BLS pubkey: {pubkey_bls}")
                continue

            sn_info['pubkey_bls'] = pubkey_bls
            sn_info['contract_id'] = contract_id

            for item in sn_info.get('contributors'):
                if 'version' in item:
                    item.pop('version')

            exit_type = entry.get('type')
            sn_info['exit_type'] = exit_type
            sn_info['deregistration_unlock_height'] = entry.get('height') + blocks_in(
                timers.get('unlock_duration_hours') * 3600) if exit_type == 'deregister' else None

            requested_unlock_height = sn_info.get('requested_unlock_height')
            sn_info['requested_unlock_height'] = requested_unlock_height if requested_unlock_height != 0 else None

            sn_info['service_node_pubkey'] = entry.get('service_node_pubkey')
            sn_info['liquidation_height'] = entry.get('liquidation_height')
            exitable_sns[contract_id] = sn_info

            for contributor in sn_info.get('contributors'):
                wallet_str = eth_format(contributor.get('address'))

                if wallet_str is None:
                    app.logger.warning(f"Wallet str is None for exit_liquidation_list_json SN: {sn_info}")
                    continue

                wallet_to_exitable_sn_map.setdefault(wallet_str, set()).add(contract_id)

    # Apply the new state if there are any
    if len(exitable_sns) > 0:
        app.logger.debug(f"Adding {len(exitable_sns)} exitable SN info to the contract_id_to_exitable_sn_map")
        app.contract_id_to_exitable_sn_map = exitable_sns

        app.logger.debug(f"Adding {len(wallet_to_exitable_sn_map)} wallet to exitable SN map")
        app.wallet_to_exitable_sn_map      = wallet_to_exitable_sn_map

    # Get the accrued rewards values for each wallet
    accrued_rewards_json = oxen_rpc_get_accrued_rewards(omq, oxend).get()
    if accrued_rewards_json['status'] != 'OK':
        app.logger.warning("{} Update SN early exit, accrued rewards request failed: {}".format(
                         date_now_str(),
                         accrued_rewards_json))
        return

    balances_key = 'balances'
    if balances_key not in accrued_rewards_json:
        app.logger.warning("{} Update SN early exit, accrued rewards request failed, 'balances' key was missing: {}".format(
                         date_now_str(),
                         accrued_rewards_json))
        return

    # Populate (Binary ETH wallet address -> accrued_rewards) table
    for address_hex, rewards in accrued_rewards_json[balances_key].items():
        # Ignore non-ethereum addresses (e.g. left oxen rewards, not relevant)
        trimmed_address_hex = address_hex[2:] if address_hex.startswith('0x') else address_hex
        if len(trimmed_address_hex) != 40:
            continue

        # Convert the address to bytes
        address_key = bytes.fromhex(trimmed_address_hex)

        # Create the info for the wallet if it doesn't exist
        if address_key not in app.wallet_map:
            app.wallet_map[address_key] = WalletInfo()

        # We only update the rewards queried from the Oxen network
        # Contract rewards are loaded on demand and cached.
        #
        # TODO It appears that doing the contract call is quite slow.
        app.wallet_map[address_key].rewards = rewards

    app.logger.info("{} Update SN finished".format(date_now_str()))


@app.route("/info")
def network_info():
    """
    Do-nothing endpoint that can be called to get just the "network" and "t" values that are
    included in every actual endpoint when you don't have any other endpoint to invoke.
    """
    return json_response({})

def get_rewards_dict_for_wallet(eth_wal):
    wallet_str = eth_format(eth_wal)

    # Convert the wallet string into bytes if it is a hex (eth address)
    wallet_key = wallet_str
    if eth_wal is not None:
        trimmed_wallet_str = wallet_str[2:] if wallet_str.startswith('0x') else wallet_str
        wallet_key         = bytes.fromhex(str(trimmed_wallet_str))

    # Retrieve the rewards earned by the wallet
    result = app.wallet_map[wallet_key] if wallet_key in app.wallet_map else WalletInfo()

    # Query the amount of rewards committed/claimed currently on the contract
    #
    # NOTE: This is done on demand because it appears to be quite slow,
    # iterating the list of wallets in one shot is quite expensive. The result
    # is cached in the contract layer to avoid these expensive calls.
    #
    # This call is completely bypassed if the wallet is not in our wallet map
    # which is populated from the Oxen rewards DB. The Oxen DB is the
    # authoritative list and this prevents an actor from spamming random
    # wallets to bloat out the python runtime memory usage.
    if result.rewards > 0:
        contract_recipient                          = app.service_node_rewards.recipients(wallet_key)
        app.wallet_map[wallet_key].contract_rewards = contract_recipient.rewards
        app.wallet_map[wallet_key].contract_claimed = contract_recipient.claimed

    return result


def generate_uuid(original_id):
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, original_id))


class Contributor(TypedDict):
    address: bytes
    amount: int
    reserved: int

class Stake(TypedDict):
    contract_id: int | None
    contributors: list[Contributor]
    deregistration_unlock_height: int | None
    earned_downtime_blocks: int
    last_reward_block_height: int | None
    last_uptime_proof: int | None
    operator_address: bytes
    operator_fee: int | None
    pubkey_bls: bytes
    requested_unlock_height: int | None
    service_node_pubkey: bytes
    staked_balance: int | None
    state: str
    # Only on multi-contributor contracts
    contract: str | None

class ErrorResponse:
    def __init__(self, message: str):
        self.error = message

def parse_stake_info(
        stake: dict,
        wallet_address: ChecksumAddress,
        confirmed_exited: bool = False,
) -> Stake | ErrorResponse:
    """
    Parses stake information and returns a standardised dictionary of stake info.

    Args:
        stake (dict): The stake data containing various stake attributes.
        wallet_address (str): The wallet address of the user.
        confirmed_exited (bool, optional): Flag indicating if the stake has been confirmed as exited. Defaults to False.

    Exceptions:
        ValueError: If the stake state cannot be determined.

    Returns:
        dict: A dictionary containing the parsed stake information.
    """
    state = None
    deregistration_unlock_height = None

    try:
        # Handles exit events
        if 'exit_type' in stake:
            exit_type = stake.get('exit_type')
            if exit_type == 'exit':
                state = (
                    "Awaiting Exit"
                    if stake.get('contract_id') and not confirmed_exited
                    else "Exited"
                )
            elif exit_type == 'deregister':
                state = "Deregistered"
                deregistration_unlock_height = stake.get('deregistration_unlock_height')
            else:
                raise ValueError(f"Invalid exit type {exit_type}")
        # Handles contract events
        elif 'contract_state' in stake:
            contract_state = stake.get('contract_state')
            if contract_state == 'awaiting_contributors':
                state = "Awaiting Contributors"
            elif contract_state == 'cancelled':
                state = "Cancelled"
            elif contract_state == 'finalized':
                raise ValueError("Finalized nodes must be filtered out before reaching this point")
            else:
                raise ValueError(f"Invalid contract state {contract_state}")
        # Handles running node info
        elif 'active' in stake and 'funded' in stake:
            state = (
                'Decommissioned'
                if not stake.get("active") and stake.get("funded")
                else 'Running'
            )
        elif 'state' in stake:
            current_state = stake.get('state')
            if current_state == 'Deregistered':
                deregistration_unlock_height = stake.get('deregistration_unlock_height')
            if confirmed_exited and current_state == 'Awaiting Exit':
                state = 'Exited'
            else:
                state = current_state
        else:
            raise ValueError("Unable to determine node state")
    except ValueError as e:
        base_msg = f"Value Error while parsing stake state for stake: \n {stake}"
        app.logger.error(f"{base_msg} \n Exception: {e}")
        return ErrorResponse(base_msg)
    except Exception as e:
        base_msg = f"Exception while parsing stake state for stake: \n {stake}"
        app.logger.error(f"{base_msg} \n Exception: {e}")
        return ErrorResponse(base_msg)

    # Process contributors and calculate staked balance
    contributors = stake.get('contributors', [])
    staked_balance = sum(
        contributor.get('amount')
        for contributor in contributors
        if eth_format(contributor.get('address')) == wallet_address
    ) or None

    # `stake-${stake.contract_id}-${stake.service_node_pubkey}-${stake.last_uptime_proof}`;
    contract_id = stake.get('contract_id')
    contract = stake.get('contract')
    contract_formatted = eth_format(contract) if contract is not None else None
    pubkey_bls = stake.get('pubkey_bls')

    # TODO: Investigate the best data to use for id generation. these ids MUST be unique for each stake.
    #
    # A pubkey_bls can have multiple stakes over time, but a pubkey_bls and (contract_id or contract) can only have
    #  one stake ever. The pubkey_bls needs to be used as its possible for a stake to not have a contract_id or
    #  contract when it exits
    unique_id = generate_uuid("{}-{}".format(pubkey_bls, contract_id if contract_formatted is None else contract_formatted))

    return {
        'unique_id': unique_id,
        'contract_id': contract_id,
        'contract': contract_formatted,
        'contributors': contributors,
        'deregistration_unlock_height': deregistration_unlock_height,
        'earned_downtime_blocks': stake.get('earned_downtime_blocks'),
        'last_reward_block_height': stake.get('last_reward_block_height'),
        'last_uptime_proof': stake.get('last_uptime_proof'),
        'liquidation_height': stake.get('liquidation_height'),
        'operator_address': stake.get('operator_address'),
        'operator_fee': stake.get('operator_fee'),
        'pubkey_bls': pubkey_bls,
        'requested_unlock_height': stake.get('requested_unlock_height'),
        'service_node_pubkey': stake.get('service_node_pubkey'),
        'staked_balance': staked_balance,
        'state': state,
        'exited': confirmed_exited or state == 'Exited',
    }


@app.route("/stakes/<eth_wallet:eth_wal>")
def get_stakes(eth_wal: str):
    try:
        if not eth_wal or not eth_utils.is_address(eth_wal):
            raise ValueError("Invalid wallet address")

        wallet_address = eth_format(eth_wal)
        app.tracked_wallet_addresses.add(wallet_address)

        # A contract id can only appear once across the lists
        added_contract_ids = set()

        parse_errors = []

        app.logger.debug(f"Fetching stakes for {wallet_address}")
        app.logger.debug(f"wallet_to_sn_map len: {len(app.wallet_to_sn_map)}")
        app.logger.debug(f"contract_id_to_sn_map len: {len(app.contract_id_to_sn_map)}")
        app.logger.debug(f"wallet_to_exitable_sn_map len: {len(app.wallet_to_exitable_sn_map)}")
        app.logger.debug(f"contract_id_to_exitable_sn_map len: {len(app.contract_id_to_exitable_sn_map)}")

        def handle_stakes(
                address_to_stakes_map: dict[ChecksumAddress, set[int]],
                contract_id_to_stake_map: dict[int, Stake],
                output_list: list[Stake],
                confirmed_exited=False,
        ):
            app.logger.debug(f"added_contract_ids: {added_contract_ids}")
            for contract_id in address_to_stakes_map.get(wallet_address, []):
                app.logger.debug(f"contract_id: {contract_id}")
                if contract_id not in added_contract_ids:
                    stake = contract_id_to_stake_map.get(contract_id)
                    parsed_stake = parse_stake_info(stake, wallet_address, confirmed_exited)
                    if isinstance(parsed_stake, ErrorResponse):
                        parse_errors.append({
                            'contract_id': contract_id,
                            'error': parsed_stake.error
                        })
                    else:
                        output_list.append(parsed_stake)
                    added_contract_ids.add(contract_id)

        stakes = []
        handle_stakes(app.wallet_to_exitable_sn_map, app.contract_id_to_exitable_sn_map, stakes)
        handle_stakes(app.wallet_to_sn_map, app.contract_id_to_sn_map, stakes)

        if wallet_address not in app.wallet_to_historical_stakes_map:
            # NOTE: This db call is only triggered once per wallet address, this is reset after the scheduled db read.
            get_db_stakes_for_wallet(wallet_address)

        historical_stakes = []
        handle_stakes(app.wallet_to_historical_stakes_map, app.contract_id_to_historical_stakes_map, historical_stakes,
                      confirmed_exited=True)

        contracts = [
            {
                "contract": addr,
                **details
            }
            for addr, details in get_contribution_contracts().items()
            if details.get('contract_state') == 'awaiting_contributors' and details.get('operator') == wallet_address
        ]

        if len(app.bls_pubkey_to_contract_id_map) == 0:
            app.logger.warning("{} bls_pubkey_to_contract_id_map is empty, fetching contract ids".format(date_now_str()))
            update_service_node_contract_ids(None)


        for contract in contracts:
            pubkey_bls = contract.get('pubkey_bls')
            if pubkey_bls is None:
                app.logger.warning(f"pubkey_bls is None for contract: {contract}")
                continue
            contract_id = app.bls_pubkey_to_contract_id_map.get(pubkey_bls)
            contract['contract_id'] = contract_id
            contract['operator_fee'] = contract.get('fee')
            contract['operator_address'] = contract.get('operator')

            stakes.append(parse_stake_info(contract, wallet_address))

        return json_response({
            "contracts": contracts,
            "historical_stakes": historical_stakes,
            "stakes": stakes,
            "wallet": vars(get_rewards_dict_for_wallet(wallet_address)),
            "error_stakes": parse_errors if len(parse_errors) > 0 else None
        })
    except ValueError as e:
        app.logger.error(f"Exception: {e}")
        return flask.abort(400, e)
    except Exception as e:
        app.logger.error(f"Exception: {e}")
        return flask.abort(500, e)


@app.route("/nodes")
def get_nodes():
    """
    Returns a list of all nodes that are running.
    """
    nodes = []
    for node in app.contract_id_to_sn_map.values():
        nodes.append(parse_stake_info(node, node['operator_address']))
    return json_response({"nodes": nodes})


# export enum NODE_STATE {
#   RUNNING = 'Running',
#   AWAITING_CONTRIBUTORS = 'Awaiting Contributors',
#   CANCELLED = 'Cancelled',
#   DECOMMISSIONED = 'Decommissioned',
#   DEREGISTERED = 'Deregistered',
#   AWAITING_EXIT = 'Awaiting Exit',
#   EXITED = 'Exited',
# }
@app.route("/nodes/<oxen_wallet:oxen_wal>")
@app.route("/nodes/<eth_wallet:eth_wal>")
def get_nodes_for_wallet(oxen_wal=None, eth_wal=None):
    assert oxen_wal is not None or eth_wal is not None
    wallet_str  = eth_format(eth_wal) if eth_wal is not None else oxen_wal

    sns   = []
    nodes = []
    for sn_index in app.wallet_to_sn_map.get(wallet_str, []):
        sn_info = app.contract_id_to_sn_map[sn_index]
        sns.append(sn_info)
        balance = {c["address"]: c["amount"] for c in sn_info["contributors"]}.get(wallet_str, 0)
        state   = 'Decommissioned' if not sn_info["active"] and sn_info["funded"] else 'Running'
        nodes.append({
            'balance':                 balance,
            'contributors':            sn_info["contributors"],
            'last_uptime_proof':       sn_info["last_uptime_proof"],
            'contract_id':             sn_info["contract_id"],
            'operator_address':        sn_info["operator_address"],
            'operator_fee':            sn_info["operator_fee"],
            'requested_unlock_height': sn_info["requested_unlock_height"],
            'last_reward_block_height':sn_info["last_reward_block_height"],
            'service_node_pubkey':     sn_info["service_node_pubkey"],
            'pubkey_bls':              sn_info["pubkey_bls"],
            'decomm_blocks_remaining': max(sn_info["earned_downtime_blocks"], 0),
            'state':                   state,
        })

    contracts = []
    if wallet_str in app.contributors:
        for address in app.contributors[wallet_str]:
            details = app.contracts[address]
            contracts.append({
                'contract_address': address,
                'details': details
            })

    # Setup the result
    result = json_response({
        "wallet":         vars(get_rewards_dict_for_wallet(wallet_str)),
        "service_nodes":  sns,
        "contracts":      contracts,
        "nodes":          nodes,
    })

    return result

@app.route("/nodes/open")
def get_contributable_contracts():
    nodes = get_contribution_contracts()
    return json_response({
        "nodes": [
            {
                "contract": addr,
                **details
            }
            for addr, details in nodes.items()
            if details.get('contract_state') == 'awaiting_contributors'
        ]
    })

@app.route("/rewards/<eth_wallet:eth_wal>", methods=["GET", "POST"])
def get_rewards(eth_wal: str):
    if flask.request.method == "GET":
        result = json_response({
            "wallet": vars(get_rewards_dict_for_wallet(eth_wal)),
        })
        return result

    if flask.request.method == "POST":
        omq, oxend = omq_connection()
        try:
            response = oxen_rpc_bls_rewards_request(omq, oxend, eth_format(eth_wal)).get()
            if response is None:
                return flask.abort(504) # Gateway timeout
            if 'status' in response:
                response.pop('status')
            if 'address' in response:
                response.pop('address')
            result = json_response({
                'result': response
            })
            return result
        except TimeoutError:
            return flask.abort(408) # Request timeout

    return flask.abort(405) # Method not allowed

@app.route("/exit/<hex64:ed25519_pubkey>")
def get_exit(ed25519_pubkey: bytes):
    omq, oxend = omq_connection()
    try:
        response = oxen_rpc_bls_exit_liquidation(omq, oxend, ed25519_pubkey, liquidate=False).get()
        if response is None:
            return flask.abort(504) # Gateway timeout
        if 'status' in response:
            response.pop('status')
        result = json_response({
            'result': response
        })
        return result
    except TimeoutError:
        return flask.abort(408) # Request timeout

@app.route("/exit_liquidation_list")
def get_exit_liquidation_list():
    try:
        array = []
        for item in app.contract_id_to_exitable_sn_map.values():
            array.append(item)

        result = json_response({
            'result': array
        })
        return result
    except TimeoutError:
        return flask.abort(408) # Request timeout

@app.route("/liquidation/<hex64:ed25519_pubkey>")
def get_liquidation(ed25519_pubkey: bytes):
    omq, oxend = omq_connection()
    try:
        response = oxen_rpc_bls_exit_liquidation(omq, oxend, ed25519_pubkey, liquidate=True).get()
        if response is None:
            return flask.abort(504) # Gateway timeout
        if 'status' in response:
            response.pop('status')
        result = json_response({
            'result': response
        })
        return result
    except TimeoutError:
        return flask.abort(408) # Request timeout


def handle_stakes_row(
        wallet_to_historical_stakes_map: dict[ChecksumAddress, set[int]],
        contract_id_to_historical_stakes_map: dict[int, Stake],
        sql_cur: sqlite3.Cursor,
):
    for row in sql_cur:
        (
            contract_id,
            last_updated,
            pubkey_bls,
            deregistration_unlock_height,
            earned_downtime_blocks,
            last_reward_block_height,
            last_uptime_proof,
            operator_address,
            operator_fee,
            requested_unlock_height,
            service_node_pubkey,
            state,
            contributor_address,
            contributor_amount,
        ) = row


        contributor_adr = eth_format(contributor_address)

        if contract_id not in contract_id_to_historical_stakes_map:
            stake = {
                'pubkey_bls': pubkey_bls,
                'contract_id': contract_id,
                'deregistration_unlock_height': deregistration_unlock_height,
                'earned_downtime_blocks': earned_downtime_blocks,
                'last_reward_block_height': last_reward_block_height,
                'last_uptime_proof': last_uptime_proof,
                'operator_address': eth_format(operator_address),
                'operator_fee': operator_fee,
                'requested_unlock_height': requested_unlock_height,
                'service_node_pubkey': service_node_pubkey,
                'state': state,
                'contributors': [],
            }
            contract_id_to_historical_stakes_map[contract_id] = stake
        else:
            stake = contract_id_to_historical_stakes_map[contract_id]

        # Add contributor info
        contributor = {
            'address': contributor_adr,
            'amount': contributor_amount,
        }
        stake['contributors'].append(contributor)
        wallet_to_historical_stakes_map.setdefault(contributor_adr, set()).add(contract_id)


def get_db_stakes_for_wallet(wallet_address: ChecksumAddress):
    """
    This exists to get the stakes for a wallet that is not in the tracked list. This should only be used when we need
    the data but the timed database read hasn't executed yet with the address in the tracked list. A wallet address
    can only call this once in between scheduled database read times.
    """
    app.logger.debug("{} get_db_stakes_for_wallet: {}".format(date_now_str(), wallet_address))
    if wallet_address in app.tmp_db_trigger_wallet_addresses:
        return

    app.tmp_db_trigger_wallet_addresses.add(wallet_address)

    with app.app_context(), get_sql() as sql:
        cur = sql.cursor()
        cur.execute(
            """
            SELECT s.*,
                   sc_contributors.address AS contributor_address,
                   sc_contributors.amount AS contributor_amount
            FROM stakes s
                JOIN stake_contributions sc_requestor ON sc_requestor.contract_id = s.id
                JOIN stake_contributions sc_contributors ON sc_contributors.contract_id = s.id
            WHERE sc_requestor.address = ?;
            """,
            (address_to_bytes(wallet_address),),
        )

        handle_stakes_row(app.wallet_to_historical_stakes_map, app.contract_id_to_historical_stakes_map, cur)


def address_to_bytes(address: str) -> bytes:
    if address.startswith("0x"):
        return bytes.fromhex(address[2:])
    else:
        return bytes.fromhex(address)


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


@timer(15)
def get_db_stakes(signum):
    app.logger.info("{} Get stakes db start".format(date_now_str()))
    wallet_to_historical_stakes_map: dict[ChecksumAddress, set[int]] = {}  # (Wallet address -> Set of contract_ids)
    contract_id_to_historical_stakes_map: dict[int, Stake] = {}  # (contract_ids -> Stake Info)

    for address_chunk in chunks(list(app.tracked_wallet_addresses), 999):  # SQLite default parameter limit is 999
        placeholders = ','.join(['?'] * len(address_chunk))
        with app.app_context(), get_sql() as sql:
            cur = sql.cursor()
            cur.execute(f"""
            SELECT DISTINCT s.*,
               sc_contributors.address AS contributor_address,
               sc_contributors.amount AS contributor_amount
            FROM stakes s
                JOIN stake_contributions sc_requestor ON sc_requestor.contract_id = s.id
                JOIN stake_contributions sc_contributors ON sc_contributors.contract_id = s.id
            WHERE sc_requestor.address IN ({placeholders});
            """,
                        address_chunk,
                        )

            handle_stakes_row(wallet_to_historical_stakes_map, contract_id_to_historical_stakes_map, cur)

    if len(wallet_to_historical_stakes_map) > 0:
        app.wallet_to_historical_stakes_map = wallet_to_historical_stakes_map
        app.contract_id_to_historical_stakes_map = contract_id_to_historical_stakes_map

    app.tmp_db_trigger_wallet_addresses.clear()

    app.logger.info("{} Get stakes db finish".format(date_now_str()))


# Debug function to load all contributor addresses into the tracked wallet addresses set
def load_contributor_addresses_into_tracked_wallet_addresses():
    with app.app_context(), get_sql() as sql:
        cur = sql.cursor()
        cur.execute("SELECT DISTINCT address FROM stake_contributions")
        for row in cur:
            app.tracked_wallet_addresses.add(row[0])

# Debug function to recover non-contributor stakes. This gets all stakes that are not in the stake_contributions table and adds them to the stake_contributions using the operator address as the contributor address.
def recover_non_contributor_stakes():
    with app.app_context(), get_sql() as sql:
        cur = sql.cursor()
        added_stakes = set()
        cur.execute("SELECT DISTINCT contract_id, address FROM stake_contributions")
        for contract_id, address in cur:
            added_stakes.add((contract_id, address))

        cur.execute("SELECT DISTINCT id, operator_address FROM stakes")
        stakes_to_recover = set()
        for contract_id, operator_address in cur:
            if (contract_id, operator_address) in added_stakes:
                continue
            stakes_to_recover.add((contract_id, operator_address))

        for contract_id, operator_address in stakes_to_recover:
            app.logger.debug(f"Recovering stake for contract_id: {contract_id}, operator_address: {operator_address}")
            cur.execute(
                """
                INSERT OR REPLACE INTO stake_contributions (contract_id, address, amount)
                VALUES                                     (?,           ?,       ?)
                """,
                (
                    contract_id,
                    operator_address,
                    20000000000000,
                )
            )

@timer(30)
def update_service_node_contract_ids(signum) -> None:
    """
    Update the map of service node contract ids to BLS public keys. This fetches the list of all service nodes from the
    Service Node Rewards contract and maps them to their corresponding contract ids.
    """
    app.logger.info("{} Updating service node contract ids".format(date_now_str()))
    [ids, bls_keys] = app.service_node_rewards.allServiceNodeIDs()
    app.logger.debug(f"Added {len(ids)} service node contract ids")
    app.bls_pubkey_to_contract_id_map = {f"{x:064x}{y:064x}": contract_id for contract_id, (x, y) in zip(ids, bls_keys)}
    app.logger.info("{} Updating service node contract ids finish. Nodes: {}".format(date_now_str(),
                                                                                     len(app.bls_pubkey_to_contract_id_map)))


@timer(60)
def insert_updated_db_stakes(signum):
    """
    Inserts or updates the stakes in the database.
    """
    app.logger.info("{} Insert or update stakes db start".format(date_now_str()))
    added_contract_ids = set()
    with app.app_context(), get_sql() as sql:
        cur = sql.cursor()
        for node in chain(app.contract_id_to_exitable_sn_map.values(), app.contract_id_to_sn_map.values()):
            stake = parse_stake_info(node, node.get('operator_address'))
            contract_id = stake.get('contract_id')
            if contract_id in added_contract_ids:
                continue
            added_contract_ids.add(contract_id)
            cur.execute(
                """
                INSERT OR REPLACE INTO stakes (id, last_updated, pubkey_bls, deregistration_unlock_height, earned_downtime_blocks, last_reward_block_height, last_uptime_proof, operator_address, operator_fee, requested_unlock_height, service_node_pubkey, state)
                                       VALUES (?,  ?,            ?,          ?,                            ?,                      ?,                        ?,                 ?,                ?,            ?,                        ?,                  ?)
                """,
                (
                    contract_id,
                    datetime.datetime.now().timestamp(),
                    stake['pubkey_bls'],
                    stake['deregistration_unlock_height'],
                    stake['earned_downtime_blocks'],
                    stake['last_reward_block_height'],
                    stake['last_uptime_proof'],
                    address_to_bytes(stake['operator_address']),
                    stake['operator_fee'],
                    stake['requested_unlock_height'],
                    stake['service_node_pubkey'],
                    stake['state'],
                )
            )

            # Create the stake contributions entry
            for contributor in stake['contributors']:
                cur.execute(
                    """
                    INSERT OR REPLACE INTO stake_contributions (contract_id, address, amount)
                    VALUES                                     (?,           ?,       ?)
                    """,
                    (
                        contract_id,
                        address_to_bytes(contributor['address']),
                        contributor.get('amount'),
                    )
                )
    added_contract_ids.clear()
    app.logger.info("{} Insert or update stakes db finish".format(date_now_str()))

# Decodes `x` into a bytes of length `length`.  `x` should be hex or base64 encoded, without
# whitespace.  Both regular and "URL-safe" base64 are accepted.  Padding is optional for base64
# values.  Throws ParseError if the input is invalid or of the wrong size.  `length` must be at
# least 5 (smaller byte values are harder or even ambiguous to distinguish between hex and base64).
def decode_bytes(k, x, length):
    assert length >= 5

    hex_len = length * 2
    b64_unpadded = (length * 4 + 2) // 3
    b64_padded = (length + 2) // 3 * 4

    app.logger.debug(f"{len(x)}, {hex_len}")
    if len(x) == hex_len and all(c in string.hexdigits for c in x):
        return bytes.fromhex(x)
    if len(x) in (b64_unpadded, b64_padded):
        if oxenc.is_base64(x):
            return oxenc.from_base64(x)
        if "-" in x or "_" in x:  # Looks like (maybe) url-safe b64
            x = x.replace("/", "_").replace("+", "-")
        if oxenc.is_base64(x):
            return oxenc.from_base64(x)
    raise ParseError(k, f"expected {hex_len} hex or {b64_unpadded} base64 characters")


def byte_decoder(length: int):
    return partial(decode_bytes, length=length)


# Takes a positive integer value required to be between irange[0] and irange[1], inclusive.  The
# integer may not be 0-prefixed or whitespace padded.
def parse_int_field(k, v, irange):
    if (
        len(v) == 0
        or not all(c in "0123456789" for c in v)
        or (len(v) > 1 and v[0] == "0")
    ):
        raise ParseError(k, "an integer value is required")
    v = int(v)
    imin, imax = irange
    if imin <= v <= imax:
        return v
    raise ParseError(k, f"expected an integer between {imin} and {imax}")


def raw_eth_addr(k, v):
    if re.fullmatch(eth_regex, v):
        if not eth_utils.is_address(v):
            raise ParseError(k, "ETH address checksum failed")
        return bytes.fromhex(v[2:])
    raise ParseError(k, "not an ETH address")


def eth_format(addr: Union[bytes, str]) -> ChecksumAddress:
    try:
        return eth_utils.to_checksum_address(addr)
    except ValueError:
        raise ParseError(addr, "Invalid ETH address")


class SNSignatureValidationError(ValueError):
    pass


def check_reg_keys_sigs(params):
    if len(
        params["pubkey_ed25519"]
    ) != 32 or not sodium.crypto_core_ed25519_is_valid_point(params["pubkey_ed25519"]):
        raise SNSignatureValidationError("Ed25519 pubkey is invalid")
    if len(params["pubkey_bls"]) != 64:  # FIXME: bls pubkey validation?
        raise SNSignatureValidationError("BLS pubkey is invalid")
    if len(params["operator"]) != 20:
        raise SNSignatureValidationError("operator address is invalid")
    contract = params.get("contract")
    if contract is not None and len(contract) != 20:
        raise SNSignatureValidationError("contract address is invalid")

    signed = (
        params["pubkey_ed25519"]
        + params["pubkey_bls"]
    )

    try:
        VerifyKey(params["pubkey_ed25519"]).verify(signed, params["sig_ed25519"])
    except nacl.exceptions.BadSignatureError:
        raise SNSignatureValidationError("Ed25519 signature is invalid")

    # FIXME: BLS verification of pubkey_bls on signed
    if False:
        raise SNSignatureValidationError("BLS signature is invalid")


class ParseError(ValueError):
    def __init__(self, field, reason):
        self.field = field
        super().__init__(f"{field}: {reason}")


class ParseMissingError(ParseError):
    def __init__(self, field):
        super().__init__(field, f"required parameter is missing")


class ParseUnknownError(ParseError):
    def __init__(self, field):
        super().__init__(field, f"unknown parameter")


class ParseMultipleError(ParseError):
    def __init__(self, field):
        super().__init__(field, f"cannot be specified multiple times")


def parse_query_params(params: dict[str, Callable[[str, str], Any]]):
    """
    Takes a dict of fields and callables such as:

        {
            "field": ("out", callable),
            ...
        }

    where:
    - `"field"` is the expected query string name
    - `callable` will be invoked as `callable("field", value)` to determined the returned value.

    On error, throws a ParseError with `.field` set to the "field" name that triggered the error.

    Notes:
    - callable should throw a ParseError for an unaccept input value.
    - if "-field" starts with "-" then the field is optional; otherwise it is an error if not
      provided.  The "-" is not included in the returned key.
    - if "field" ends with "[]" then the value will be an array of values returned by the callable,
      and the parameter can be specified multiple times.  Otherwise a value can be specified only
      once.  The "[]" is not included in the returned key.
    - you can do both of the above: "-field[]" will allow the value to be provided zero or more
      times; the value will be omitted if not present in the input, and an array (under the "field")
      key if provided at least once.
    """

    parsed = {}

    param_map = {
        k.removeprefix("-").removesuffix("[]"): (
            k.startswith("-"),
            k.endswith("[]"),
            cb,
        )
        for k, cb in params.items()
    }

    for k, v in flask.request.values.items(multi=True):
        found = param_map.get(k)
        if found is None:
            raise ParseUnknownError(k)

        _, multi, callback = found

        if multi:
            parsed.setdefault(k, []).append(callback(k, v) if callback else v)
        elif k not in parsed:
            parsed[k] = callback(k, v) if callback else v
        else:
            raise ParseMultipleError(k)

    for k, p in param_map.items():
        optional = p[0]
        if not optional and k not in flask.request.values:
            raise ParseMissingError(k)

    return parsed


@app.route("/store/<hex64:sn_pubkey>", methods=["GET", "POST"])
def store_registration(sn_pubkey: bytes):
    """
    Stores (or replaces) the pubkeys/signatures associated with a service node that are needed to
    call the smart contract to create a SN registration.  These pubkeys/signatures are stored
    indefinitely, allowing the operator to call them up whenever they like to re-submit a
    registration for the same node.  There is nothing confidential here: the values will be publicly
    broadcast as part of the registration process already, and are constructed in such a way that
    only the operator wallet can submit a registration using them.

    This works for both solo registrations and multi-registrations: for the latter, a contract
    address is passed in the "c" parameter.  If omitted, the details are stored for a solo
    registration.  (One of each may be stored at a time for each pubkey).

    The distinction at the SN layer is that contract registrations sign the contract address while
    solo registrations sign the operator address.  For submission to the blockchain, a contract
    stake requires an additional interaction through a multi-contributor contract while solo
    registrations can call the staking contract directly.
    """

    try:
        params = parse_query_params(
            {
                "pubkey_bls": byte_decoder(64),
                "sig_ed25519": byte_decoder(64),
                "sig_bls": byte_decoder(128),
                "-contract": raw_eth_addr,
                "operator": raw_eth_addr,
            }
        )

        params["pubkey_ed25519"] = sn_pubkey

        check_reg_keys_sigs(params)
    except ValueError as e:
        raise e
        return json_response({"error": f"Invalid registration: {e}"})

    with get_sql() as sql:
        cur = sql.cursor()
        cur.execute(
            """
            INSERT OR REPLACE INTO registrations (pubkey_ed25519, pubkey_bls, sig_ed25519, sig_bls, operator, contract)
                                          VALUES (?,              ?,          ?,           ?,       ?,        ?)
            """,
            (
                sn_pubkey,
                params["pubkey_bls"],
                params["sig_ed25519"],
                params["sig_bls"],
                params["operator"],
                params.get("contract"),
            ),
        )

    params["operator"] = eth_utils.to_checksum_address(params["operator"])
    if "contract" in params:
        params["contract"] = eth_utils.to_checksum_address(params["contract"])
        params["type"] = "contract"
    else:
        params["type"] = "solo"

    return json_response({"success": True, "registration": params})


@app.route("/registrations/<hex64:sn_pubkey>")
def sn_pubkey_registrations(sn_pubkey: bytes) -> flask.Response:
    """
    Retrieves stored registration(s) for the given service node pubkey.

    This returns an array in the "registrations" field containing either one or two registration
    info dicts: a solo registration (if known) and a multi-contributor contract registration (if
    known).  These are sorted by timestamp of when the registration was last received/updated.

    Fields in each dict:
    - "type": either "solo" or "contract"
    - "operator": the operator address; for "type": "contract" this is merely informative, for
      "type": "solo" this is a signed part of the registration.
    - "contract": the contract address, for "type": "contract" and omitted for "type": "solo".
    - "pubkey_ed25519": the primary SN pubkey, in hex.
    - "pubkey_bls": the SN BLS pubkey, in hex.
    - "sig_ed25519": the SN pubkey signed registration signature.
    - "sig_bls": the SN BLS pubkey signed registration signature.
    - "timestamp": the unix timestamp when this registration was received (or last updated)

    Returns the JSON response with the 'registrations' for the given 'sn_pubkey'.
    """

    reg_array = []
    with get_sql() as sql:
        cur = sql.cursor()
        cur.execute(
            """
            SELECT pubkey_bls, sig_ed25519, sig_bls, operator, contract, timestamp
            FROM registrations
            WHERE pubkey_ed25519 = ?
            ORDER BY timestamp DESC
            """,
            (sn_pubkey,),
        )

        for pubkey_bls, sig_ed25519, sig_bls, operator, contract, timestamp in cur:
            reg_array.append({
                "type":           "solo" if contract is None else "contract",
                "pubkey_ed25519": sn_pubkey,
                "pubkey_bls":     pubkey_bls,
                "sig_ed25519":    sig_ed25519,
                "sig_bls":        sig_bls,
                "operator":       operator,
                "timestamp":      timestamp,
                "contract":       "" if contract is None else contract,
            })

    result = json_response({"registrations": reg_array})
    return result

@app.route("/registrations/<eth_wallet:operator>")
def operator_registrations(operator: str):
    """
    Retrieves stored registration(s) for the given 'operator'.

    This returns an array in the "registrations" field containing as many registrations as are
    current stored for the given operator wallet, sorted from most to least recently submitted.

    Fields are the same as the version of this endpoint that takes a SN pubkey.

    Returns the JSON response with the 'registrations' for the given 'operator'.
    """

    reg_array      = []
    operator_bytes = bytes.fromhex(operator[2:])

    with get_sql() as sql:
        cur = sql.cursor()
        cur.execute(
            """
            SELECT pubkey_ed25519, pubkey_bls, sig_ed25519, sig_bls, contract, timestamp
            FROM registrations
            WHERE operator = ?
            ORDER BY timestamp DESC
            """,
            (operator_bytes,),
        )
        for pubkey_ed25519, pubkey_bls, sig_ed25519, sig_bls, contract, timestamp in cur:
            reg_array.append({
                "type":           "solo" if contract is None else "contract",
                "pubkey_ed25519": pubkey_ed25519,
                "pubkey_bls":     pubkey_bls,
                "sig_ed25519":    sig_ed25519,
                "sig_bls":        sig_bls,
                "operator":       operator,
                "timestamp":      timestamp,
                "contract":       "" if contract is None else contract,
            })

    result = json_response({'registrations': reg_array})
    return result


def check_stakes(stakes, total, stakers, max_stakers):
    if len(stakers) != len(stakes):
        raise ValueError(f"s and S have different lengths")
    if len(stakers) < 1:
        raise ValueError(f"at least one s/S value pair is required")
    if len(stakers) > max_stakers:
        raise ValueError(f"too many stakers ({len(stakers)} > {max_stakers})")
    if sum(stakes) > total:
        raise ValueError(f"total stake is too large ({sum(stakes)} > total)")
    if len(set(stakers)) != len(stakers):
        raise ValueError(f"duplicate staking addresses in staker list")

    remaining_stake = total
    remaining_spots = max_stakers

    for i in range(len(stakes)):
        reqd = remaining_stake // (4 if i == 0 else remaining_spots)
        if stakes[i] < reqd:
            raise ValueError(
                "reserved stake [i] ({stakers[i]}) is too low ({stakes[i]} < {reqd})"
            )
        remaining_stake -= stakes[i]
        remaining_spots -= 1

def format_currency(units: int, decimal: int = 9):
    """
    Formats an atomic currency unit to `decimal` decimal places.  The conversion is lossless (i.e.
    it does not use floating point math or involve any truncation or rounding
    """
    base = 10**decimal
    app.logger.debug(f"units: {units}, base: {base}, decimal: {decimal}, {units//base}")
    frac = units % base
    frac = "" if frac == 0 else f".{frac:0{decimal}d}".rstrip("0")
    return f"{units // base}{frac}"


def parse_currency(k, val: str, decimal: int = 9):
    """
    Losslessly parses a currency value such as 1.23 into an atomic integer value such as 1000000023.
    """
    pieces = val.split(".")
    if len(pieces) > 2 or not all(re.fullmatch(r"\d+", p) for p in pieces):
        raise ParseError(k, "Invalid currency amount")
    whole = int(pieces[0])
    if len(pieces) > 1:
        frac = pieces[1]
        if len(frac) > decimal:
            frac = frac[0:decimal]
        elif len(frac) < decimal:
            frac = frac.ljust(decimal, "0")
        frac = int(frac)
    else:
        frac = 0

    return whole * 10**decimal + frac


def error_response(code, **err):
    """
    Error codes that can be returned to a client when validating registration details.  The `code`
    is a short string that uniquely defines the error; some errors have extra parameters (passed
    into the `err` kwargs).  This method formats the error, then returns a dict such as:

        { "code": "short_code", "error": "English string", **err }

    This is returned, typically as an "error" key, by various endpoints.

    As a special value, if a `detail` key is present in err then the usual error will have ":
    {detail}" appended to it (the detail will also be passed along separately).
    """

    err["code"] = code
    match code:
        case "bad_request":
            msg = "Invalid request parameters"
        case "invalid_op_addr":
            msg = "Invalid operator address"
        case "invalid_op_stake":
            msg = "Invalid/unparseable operator stake"
        case "wrong_op_stake":
            # For a solo node that doesn't contribute the exact requirement
            msg = f"Invalid operator stake: exactly {format_currency(err['required'])} {TOKEN_NAME} is required for a solo node"
        case "insufficient_op_stake":
            network_info = get_info()
            msg = f"Insufficient operator stake: at least {format_currency(err['minimum'])} ({err['minimum'] / network_info['staking_requirement'] * 100}%) is required"
        case "invalid_contract_addr":
            msg = "Invalid contract address"
        case "invalid_res_addr":
            msg = f"Invalid reserved contributor address {err['index']}: {err['address']}"
        case "invalid_res_stake":
            msg = f"Invalid/unparseable reserved contributor amount for contributor {err['index']} ({err['address']})"
        case "insufficient_res_stake":
            msg = f"Insufficient reserved contributor stake: contributor {err['index']} ({err['address']}) must contribute at least {format_currency(err['minimum'])}"
        case "too_much":
            # for multi-contributor (solo node would get wrong_op_stake instead)
            msg = f"Total node reserved contributions are too large: {format_currency(err['total'])} exceeds the maximum stake {format_currency(err['maximum'])}"
        case "too_many":
            msg = f"Too many reserved contributors: only {err['max_contributors']} contributor spots are possible"
        case "invalid_fee":
            msg = "Invalid fee"
        case "signature":
            msg = "Invalid service node registration pubkeys/signatures"
        case _:
            msg = None

    err["error"] = f"{msg}: {err['detail']}" if "detail" in err else msg

    return json_response({"error": err})


@app.route("/validate")
def validate_registration():
    """
    Validates a registration including fee, stakes, and reserved spot requirements.  This does not
    use stored registration info at all; all information has to be submitted as part of the request.
    The data is not stored.

    Parameters for both types of stakes:
    - "pubkey_ed25519"
    - "pubkey_bls"
    - "sig_ed25519"
    - "sig_bls"
    The above are as provided by oxend for the registration.  Can be hex or base64.

    - "operator" -- the operator wallet address
    - "stake" -- the amount the operator will stake.  For a solo stake, this must be exactly equal
      to the staking requirement, but for a multi-contribution node it can be less.

    For a multi-contribution node the following must additionally be passed:
    - "contract" -- the ETH address of the multi-contribution staking contract for this node.
    - "reserved" -- optional list of reserved contributor wallets.
    - "res_stake" -- list of reserved contributor stakes.  This must be the same length and order as
      `"reserved"`.

    Various checks are performed to look for registration errors; if no errors are found then the
    result contains the key "success": true.  Otherwise the key "error" will be set to an error dict
    indicating the error that was detected.  See `error_response` for details.
    """

    network_info       = get_info()
    max_stake          = network_info['staking_requirement']
    min_operator_stake = network_info['min_operator_stake']
    max_stakers        = network_info['max_stakers']

    try:
        params = parse_query_params(
            {
                "pubkey_ed25519": byte_decoder(32),
                "pubkey_bls": byte_decoder(64),
                "sig_ed25519": byte_decoder(64),
                "sig_bls": byte_decoder(128),
                "-contract": raw_eth_addr,
                "operator": raw_eth_addr,
                "stake": parse_currency,
                "-res_addr[]": None,
                "-res_stake[]": None,
                "-fee": None,
            }
        )
    except (ParseMissingError, ParseUnknownError, ParseMultipleError) as e:
        return error_response("bad_request", field=e.field, detail=str(e))
    except ParseError as e:
        code = None
        match e.field:
            case f if f.startswith("pubkey_") or f.startswith("sig_"):
                return error_response("signature", field=f, detail=str(e))
            case "operator":
                return error_response("invalid_op_addr", detail=str(e))
            case "stake":
                return error_response("invalid_op_stake")
            case "contract":
                return error_response("invalid_contract_addr")
            case f:
                return error_response("bad_request", field=f, detail=str(e))

    try:
        check_reg_keys_sigs(params)
    except SNSignatureValidationError as e:
        return error_response("signature", detail=str(e))

    solo = "contract" not in params

    for k in ("addr", "stake"):
        params.setdefault(f"res_{k}", [])

    if solo and params["res_addr"]:
        return error_response(
            "invalid_contract_addr",
            detail="the contract address is required for multi-contributor registrations",
        )

    if solo and "fee" in params:
        return error_response(
            "invalid_fee", detail="fee is not applicable to a solo node registration"
        )
    elif "fee" not in params:
        return error_response(
            "invalid_fee",
            detail="fee is required for a multi-contribution registration",
        )
    else:
        fee = params["fee"]
        fee = int(fee) if re.fullmatch(r"\d+", fee) else -1
        if not 0 <= fee <= 10000:
            return error_response(
                "invalid_fee",
                detail="fee must be an integer between 0 and 10000 (= 100.00%)",
            )

    if len(params["res_addr"]) != len(params["res_stake"]):
        return error_response(
            "bad_request",
            field="res_addr",
            detail="mismatched reserved address/stake lists",
        )

    reserved = []
    for i, (addr, stake) in enumerate(zip(params["res_addr"], params["res_stake"])):
        try:
            eth = raw_eth_addr("res_addr", addr)
        except ValueError:
            return error_response("invalid_res_addr", address=eth_format(addr), index=i+1)
        try:
            amt = parse_currency("res_stake", stake)
        except ValueError:
            return error_response(
                "invalid_res_stake", address=eth_format(addr), index=i+1
            )

        reserved.append((eth, amt))

    total_reserved = params["stake"] + sum(stake for _, stake in reserved)
    if solo:
        if total_reserved != max_stake:
            return error_response(
                "wrong_op_stake", stake=total_reserved, required=max_stake
            )
    else:
        if params["stake"] < min_operator_stake:
            return error_response(
                "insufficient_op_stake", stake=params["stake"], minimum=min_operator_stake
            )
        if total_reserved > max_stake:
            return error_response("too_much", total=total_reserved, maximum=max_stake)
        if 1 + len(reserved) > max_stakers:
            return error_response("too_many", max_contributors=max_stakers - 1)

        remaining_stake = max_stake - params["stake"]
        remaining_spots = max_stakers - 1

        for i, (addr, amt) in enumerate(reserved):
            # integer math ceiling:
            min_contr = (remaining_stake + remaining_spots - 1) // remaining_spots
            if amt < min_contr:
                return error_response(
                    "insufficient_res_stake",
                    index=i+1,
                    address=eth_format(addr),
                    minimum=min_contr,
                )
            remaining_stake -= amt
            remaining_spots -= 1

    res = {"success": True}

    if not solo:
        res["remaining_contribution"] = remaining_stake
        res["remaining_spots"] = remaining_spots
        res["remaining_min_contribution"] = (
            remaining_stake + remaining_spots - 1
        ) // remaining_spots

    return json_response(res)

def bootstrap():
    update_service_node_contract_ids(None)

bootstrap()
