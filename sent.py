#!/usr/bin/env python3

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

from typing           import Callable, Any, Union
from functools        import partial
from werkzeug.routing import BaseConverter
from nacl.signing     import VerifyKey
from omq              import FutureJSON, omq_connection
from timer            import timer

from contracts.reward_rate_pool                  import RewardRatePoolInterface
from contracts.service_node_contribution         import ContributorContractInterface
from contracts.service_node_contribution_factory import ServiceNodeContributionFactory
from contracts.service_node_rewards              import ServiceNodeRewardsInterface, ServiceNodeRewardsRecipient

# Make a dict of config.* to pass to templating
conf = {x: getattr(config, x) for x in dir(config) if not x.startswith("__")}

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
    result = FutureJSON(omq, oxend, 'rpc.bls_exit_liquidation_request', args={'pubkey': ed25519_pubkey.hex(), 'liquidate': liquidate})
    return result

def get_oxen_rpc_bls_exit_liquidation_list(omq, oxend):
    result = FutureJSON(omq, oxend, 'rpc.bls_exit_liquidation_list').get()
    if result is not None:
        for entry in result:
            # TODO: Unify the naming and fields on the oxen-core side, prefer the names used in
            # get_service_nodes which is what all end-user consuming applications are using,
            # consistency is important.
            if 'bls_public_key' in entry['info']:
                entry['info']['pubkey_bls'] = entry['info']['bls_public_key']
                entry['info'].pop('bls_public_key')
            for item in entry['info']['contributors']:
                item.pop('version')
            if 'state' not in entry:
                entry['state'] = "Voluntary Deregistration" if entry['type'] == 'exit' else "Deregistered"
                entry.pop('type')
            if 'version' in entry:
                entry.pop('version')

    return result

class App(flask.Flask):
    def __init__(self):
        super().__init__(__name__)

        self.service_node_rewards              = ServiceNodeRewardsInterface(config.PROVIDER_ENDPOINT, config.SERVICE_NODE_REWARDS_ADDRESS)
        self.reward_rate_pool                  = RewardRatePoolInterface(config.PROVIDER_ENDPOINT, config.REWARD_RATE_POOL_ADDRESS)
        self.service_node_contribution_factory = ServiceNodeContributionFactory(config.PROVIDER_ENDPOINT, config.SERVICE_NODE_CONTRIBUTION_FACTORY_ADDRESS)
        self.service_node_contribution         = ContributorContractInterface(config.PROVIDER_ENDPOINT)

        self.sn_list                           = {} # Stores Oxen RPC get_service_nodes result (augmented w/ extra metadata like SN contract ID)
        self.wallet_to_sn_list                 = {} # (Wallet address -> List of SN's they own or contribute to)
        self.wallet_to_exitable_sn_list        = {} # (Wallet address -> List of SN's they can liquidate/exit)
        self.contributors                      = {}
        self.contracts                         = {}

        self.sn_map                            = {} # (Binary SN key_ed25519     -> oxen.rpc.service_node_states dict: info for SN)
        self.wallet_map                        = {} # (Binary ETH wallet address -> WalletInfo)
        git_rev                                = subprocess.run(["git", "rev-parse", "--short=9", "HEAD"], stdout=subprocess.PIPE, text=True)
        self.git_rev                           = git_rev.stdout.strip() if git_rev.returncode == 0 else "(unknown)"

        sql = sqlite3.connect(config.sqlite_db)
        cursor = sql.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
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
            """);

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS registrations_operator_idx ON registrations(operator);
        """)

        cursor.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS registration_pk_multi_idx ON registrations(pubkey_ed25519, contract IS NULL);
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS contribution_contracts (
                id INTEGER PRIMARY KEY NOT NULL,
                contract_address TEXT NOT NULL,
                status INTEGER DEFAULT 1,
                timestamp FLOAT NOT NULL DEFAULT ((julianday('now') - 2440587.5)*86400.0), /* unix epoch */

                CHECK(length(contract_address) == 42)  -- Assuming Ethereum addresses
            );
        """)

        cursor.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS contribution_contract_address_idx ON contribution_contracts(contract_address);
         """)
        cursor.close()
        sql.close()


app = App()

def get_sql():
    if "db" not in flask.g:
        flask.g.sql = sqlite3.connect(config.sqlite_db)
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


b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
oxen_wallet_regex = (
    f"T[{b58}]{{96}}" if config.testnet
    else f"dV[{b58}]{{95}}" if config.devnet
    else f"ST[{b58}]{{95}}" if config.stagenet
    else f"L[{b58}]{{94}}"
)


class OxenConverter(BaseConverter):
    def __init__(self, url_map):
        super().__init__(url_map)
        self.regex = oxen_wallet_regex


class OxenEthConverter(BaseConverter):
    def __init__(self, url_map):
        super().__init__(url_map)
        self.regex = f"{eth_regex}|{oxen_wallet_regex}"


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


# FIXME: this staking requirement value is just a placeholder for now.  We probably also want to
# expose and retrieve this from oxend rather than hard coding it here.
MAX_STAKE = 120_000000000
MIN_OP_STAKE = MAX_STAKE // 4
MAX_STAKERS = 10
TOKEN_NAME = "SENT"


def get_info():
    omq, oxend = omq_connection()
    info = FutureJSON(omq, oxend, "rpc.get_info").get()

    # TODO: get_info is returning the wrong top_block_hash, it isn't _actually_
    # the top block hash in stagenet atleast. Mainnet looks like it's producing
    # the correct values.
    result = {
        **{
            k: v
            for k, v in info.items()
            if k in ("nettype", "hard_fork", "version")
        },
        "staking_requirement": MAX_STAKE,
        "min_operator_stake": MIN_OP_STAKE,
        "max_stakers": MAX_STAKERS,
    }

    blk_header_result = FutureJSON(omq,
                                   oxend,
                                   "rpc.get_last_block_header",
                                   args={
                                       'fill_pow_hash': False,
                                       'get_tx_hashes': False
                                   }).get()

    blk_header                = blk_header_result['block_header']
    result['block_timestamp'] = blk_header['timestamp']
    result['block_height']    = blk_header['height']
    result['block_hash']      = blk_header['hash']
    return result


def json_response(vals):
    """
    Takes a dict, adds some general info fields to it, and jsonifies it for a flask route function
    return value.  The dict gets passed through `hexify` first to convert any bytes values to hex.
    """

    hexify(vals)

    return flask.jsonify({**vals, "network": get_info(), "t": time.time()})

@timer(10, target="worker1")
def fetch_contribution_contracts(signum):
    app.logger.warning("{} Fetch contribution contracts start".format(date_now_str()))
    with app.app_context(), get_sql() as sql:
        cursor = sql.cursor()

        new_contracts = app.service_node_contribution_factory.get_latest_contribution_contract_events()

        for event in new_contracts:
            contract_address = event.args.contributorContract
            cursor.execute(
                """
                INSERT INTO contribution_contracts (contract_address) VALUES (?)
                ON CONFLICT (contract_address) DO NOTHING
                """,
                (contract_address,)
            )
        sql.commit()
    app.logger.warning("{} Fetch contribution contracts finish".format(date_now_str()))

@timer(30)
def fetch_contract_statuses(signum):
    app.logger.warning("{} Update Contract Statuses Start".format(date_now_str()))
    with app.app_context(), get_sql() as sql:
        cursor = sql.cursor()
        cursor.execute("SELECT contract_address FROM contribution_contracts")
        contract_addresses = cursor.fetchall()
        app.contributors = {}
        app.contracts = {}

        for (contract_address,) in contract_addresses:
            contract_interface = app.service_node_contribution.get_contract_instance(contract_address)

            # Fetch statuses and other details
            is_finalized        = contract_interface.is_finalized()
            is_cancelled        = contract_interface.is_cancelled()
            bls_pubkey          = contract_interface.get_bls_pubkey()
            service_node_params = contract_interface.get_service_node_params()
            #contributor_addresses = contract_interface.get_contributor_addresses()
            total_contributions = contract_interface.total_contribution()
            contributions       = contract_interface.get_individual_contributions()

            app.contracts[contract_address] = {
                'finalized': is_finalized,
                'cancelled': is_cancelled,
                'bls_pubkey': bls_pubkey,
                'fee': service_node_params['fee'],
                'service_node_pubkey': service_node_params['serviceNodePubkey'],
                'service_node_signature': service_node_params['serviceNodeSignature'],
                'contributions': [
                    {"address": addr, "amount": amt} for addr, amt in contributions.items()
                ],
                'total_contributions': total_contributions,
            }

            for address in contributions.keys():
                wallet_key = eth_format(address)
                if address not in app.contributors:
                    app.contributors[wallet_key] = []
                if contract_address not in app.contributors[wallet_key]:
                    app.contributors[wallet_key].append(contract_address)

    app.logger.warning("{} Update Contract Statuses Finish".format(date_now_str()))

@timer(10)
def fetch_service_nodes(signum):
    app.logger.warning("{} Update SN Start".format(date_now_str()))
    omq, oxend            = omq_connection()

    # Create dictionary of (bls_pubkey -> contract_id)
    [ids, bls_keys]    = app.service_node_rewards.allServiceNodeIDs()
    formatted_bls_keys = {f"{x:064x}{y:064x}": contract_id for contract_id, (x, y) in zip(ids, bls_keys)}

    # Generate new state
    sn_info_list      = get_sns_future(omq, oxend).get()["service_node_states"]
    wallet_to_sn_list = {}
    sn_map            = {};
    for index, sn_info in enumerate(sn_info_list):
        # Add the SN contract ID to the sn_info dict
        sn_info["contract_id"] = formatted_bls_keys.get(sn_info["pubkey_bls"])

        # Creating (Binary SN key_ed25519 -> oxen.rpc.service_node_states) table
        service_node_pubkey_hex     = sn_info['service_node_pubkey']
        service_node_pubkey         = bytes.fromhex(service_node_pubkey_hex)
        sn_map[service_node_pubkey] = sn_info

        contributors = {c["address"]: c["amount"] for c in sn_info["contributors"]}

        # Creating (wallet -> [SN's the wallet owns]) table
        for wallet_key in contributors.keys():
            if len(wallet_key) == 40:
                wallet_key = eth_format(wallet_key)

            if wallet_key not in wallet_to_sn_list:
                wallet_to_sn_list[wallet_key] = []
            wallet_to_sn_list[wallet_key].append(index)

    # Apply the new state at the end together
    app.sn_map            = sn_map
    app.wallet_to_sn_list = wallet_to_sn_list
    app.sn_list           = sn_info_list

    # Get list of SNs that can be liquidated/exited
    exit_liquidation_list_json = get_oxen_rpc_bls_exit_liquidation_list(omq, oxend)

    # Create a mapping from (wallet -> [List of SNs that can be exited for that wallet])
    app.wallet_to_exitable_sn_list = {}
    if exit_liquidation_list_json is not None:
        for entry in exit_liquidation_list_json:
            entry["contract_id"] = formatted_bls_keys.get(entry['info']["pubkey_bls"])
            for contributor in entry['info']["contributors"]:
                wallet_str = eth_format(contributor["address"])
                if wallet_str not in app.wallet_to_exitable_sn_list:
                    app.wallet_to_exitable_sn_list[wallet_str] = []
                app.wallet_to_exitable_sn_list[wallet_str].append(entry)

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

    app.logger.warning("{} Update SN finished".format(date_now_str()))

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

# export enum NODE_STATE {
  # RUNNING = 'Running',
  # AWAITING_CONTRIBUTORS = 'Awaiting Contributors',
  # CANCELLED = 'Cancelled',
  # DECOMMISSIONED = 'Decommissioned',
  # DEREGISTERED = 'Deregistered',
  # VOLUNTARY_DEREGISTRATION = 'Voluntary Deregistration',
# }
@app.route("/nodes/<oxen_wallet:oxen_wal>")
@app.route("/nodes/<eth_wallet:eth_wal>")
def get_nodes_for_wallet(oxen_wal=None, eth_wal=None):
    assert oxen_wal is not None or eth_wal is not None
    wallet_str  = eth_format(eth_wal) if eth_wal is not None else oxen_wal

    sns   = []
    nodes = []
    if wallet_str in app.wallet_to_sn_list:
        for sn_index in app.wallet_to_sn_list[wallet_str]:
            sn_info = app.sn_list[sn_index]
            sns.append(sn_info)
            balance = {c["address"]: c["amount"] for c in sn_info["contributors"]}.get(wallet_str, 0)
            state   = 'Decommissioned' if not sn_info["active"] and sn_info["funded"] else 'Running'
            nodes.append({
                'balance':                 balance,
                'contributors':            sn_info["contributors"],
                'last_uptime_proof':       sn_info["last_uptime_proof"],
                'contract_id':             sn_info["contract_id"],
                'operator_address':        sn_info["operator_address"],
                'operator_fee':            sn_info["portions_for_operator"],
                'requested_unlock_height': sn_info["requested_unlock_height"],
                'service_node_pubkey':     sn_info["service_node_pubkey"],
                'decomm_blocks_remaining': max(sn_info["earned_downtime_blocks"], 0),
                'state':                   state,
            })

    if wallet_str in app.wallet_to_exitable_sn_list:
        entry   = app.wallet_to_exitable_sn_list[wallet_str]

        for exit_sn in entry:
            balance = 0
            for item in exit_sn['info']['contributors']:
                if eth_format(item['address']) == wallet_str:
                    balance += item["amount"]

            nodes.append({
                'balance':                 balance,
                'contributors':            exit_sn['info']['contributors'],
                # TODO: Missing 'last_uptime_proof':       exit_sn['info']['last_uptime_proof'],
                'contract_id':             exit_sn['contract_id'],
                'operator_address':        exit_sn['info']['operator_address'],
                'operator_fee':            exit_sn['info']['portions_for_operator'],
                'requested_unlock_height': exit_sn['info']['requested_unlock_height'],
                'service_node_pubkey':     exit_sn['service_node_pubkey'],
                'liquidation_height':      exit_sn['liquidation_height'],
                'state':                   exit_sn['state'],
                'event_height':            exit_sn['height'],
            })

    contracts = []
    if wallet_str in app.contributors:
        for address in app.contributors[wallet_str]:
            details = app.contracts[address]
            contracts.append({
                'contract_address': address,
                'details': details
            })
            if details["finalized"]:
                continue
            state = 'Cancelled' if details["cancelled"] else 'Awaiting Contributors'
            nodes.append({
                'balance':                 details["contributions"].get(wallet_str, 0),
                'contributors':            details["contributions"],
                'last_uptime_proof':       0,
                'operator_address':        details["contributor_addresses"][0],
                'operator_fee':            details["service_node_params"]["fee"],
                'requested_unlock_height': 0,
                'service_node_pubkey':     details["service_node_params"]["serviceNodePubkey"],
                'state':                   state,
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
    return json_response({
        "nodes": [
            {
                "contract": addr,
                **details
            }
            for addr, details in app.contracts.items()
            if not details['finalized'] and not details['cancelled']
            # FIXME: we should also filter out reserved contracts
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
        omq, oxend = omq_connection();
        try:
            response = oxen_rpc_bls_rewards_request(omq, oxend, eth_format(eth_wal)).get()
            if response is None:
                return flask.abort(504) # Gateway timeout
            if 'status' in response:
                response.pop('status')
            if 'address' in response:
                response.pop('address')
            result = json_response({
                'bls_rewards_response': response
            })
            return result
        except TimeoutError:
            return flask.abort(408) # Request timeout

    return flask.abort(405) # Method not allowed

@app.route("/exit/<hex64:ed25519_pubkey>")
def get_exit(ed25519_pubkey: bytes):
    omq, oxend = omq_connection();
    try:
        response = oxen_rpc_bls_exit_liquidation(omq, oxend, ed25519_pubkey, liquidate=False).get()
        if response is None:
            return flask.abort(504) # Gateway timeout
        if 'status' in response:
            response.pop('status')
        result = json_response({
            'bls_exit_response': response
        })
        return result
    except TimeoutError:
        return flask.abort(408) # Request timeout

@app.route("/exit_liquidation_list")
def get_exit_liquidation_list():
    omq, oxend = omq_connection();
    try:
        response = get_oxen_rpc_bls_exit_liquidation_list(omq, oxend)
        if response is None:
            return flask.abort(504) # Gateway timeout
        result = json_response({
            'bls_exit_liquidation_list_response': response
        })
        return result
    except TimeoutError:
        return flask.abort(408) # Request timeout

@app.route("/liquidation/<hex64:ed25519_pubkey>")
def get_liquidation(ed25519_pubkey: bytes):
    omq, oxend = omq_connection();
    try:
        response = oxen_rpc_bls_exit_liquidation(omq, oxend, ed25519_pubkey, liquidate=True).get()
        if response is None:
            return flask.abort(504) # Gateway timeout
        if 'status' in response:
            response.pop('status')
        result = json_response({
            'bls_liquidation_response': response
        })
        return result
    except TimeoutError:
        return flask.abort(408) # Request timeout

# Decodes `x` into a bytes of length `length`.  `x` should be hex or base64 encoded, without
# whitespace.  Both regular and "URL-safe" base64 are accepted.  Padding is optional for base64
# values.  Throws ParseError if the input is invalid or of the wrong size.  `length` must be at
# least 5 (smaller byte values are harder or even ambiguous to distinguish between hex and base64).
def decode_bytes(k, x, length):
    assert length >= 5

    hex_len = length * 2
    b64_unpadded = (length * 4 + 2) // 3
    b64_padded = (length + 2) // 3 * 4

    print(f"DEBGUG: {len(x)}, {hex_len}")
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


def eth_format(addr: Union[bytes, str]):
    try:
        return eth_utils.to_checksum_address(addr)
    except ValueError:
        raise ParseError("Invalid ETH address")


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
    print(f"units: {units}, base: {base}, decimal: {decimal}, {units//base}")
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
            msg = f"Insufficient operator stake: at least {format_currency(err['minimum'])} ({err['minimum'] / MAX_STAKE * 100}%) is required"
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

    stakers = []
    stakes = []

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
        if total_reserved != MAX_STAKE:
            return error_response(
                "wrong_op_stake", stake=total_reserved, required=MAX_STAKE
            )
    else:
        if params["stake"] < MIN_OP_STAKE:
            return error_response(
                "insufficient_op_stake", stake=params["stake"], minimum=MIN_OP_STAKE
            )
        if total_reserved > MAX_STAKE:
            return error_response("too_much", total=total_reserved, maximum=MAX_STAKE)
        if 1 + len(reserved) > MAX_STAKERS:
            return error_response("too_many", max_contributors=MAX_STAKERS - 1)

        remaining_stake = MAX_STAKE - params["stake"]
        remaining_spots = MAX_STAKERS - 1

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
