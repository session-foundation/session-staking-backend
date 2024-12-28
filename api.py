#!/usr/bin/env python3
import dataclasses
import statistics
import flask
import time
import eth_utils
import subprocess

import config
from db.read import DBReader
from log import Log
from oxen.rpc import OxenRPC
from registration.read import DBReaderRegistrations
from util.data import DataManager
from util.parse import Hex64Converter, hexify, EthConverter

class App(flask.Flask):
    def __init__(self, name):
        super().__init__(__name__)
        log = Log(name, enable_perf=config.backend.performance_logging)
        log.set_level(config.backend.log_level)
        git_rev = subprocess.run(
            ["git", "rev-parse", "--short=9", "HEAD"], stdout=subprocess.PIPE, text=True
        )
        self.git_rev = git_rev.stdout.strip() if git_rev.returncode == 0 else "(unknown)"

        # Creates a generic logger to pipe other packages logs into the main app logger
        generic_logger = Log(None)
        generic_logger.set_level(
            config.backend.log_level_generic
            if config.backend.log_level_generic is not None
            else config.backend.log_level
        )
        self.log = log.logger

        self.db_reader = DBReader(
            db_path=config.backend.sqlite_db,
            log_level=config.backend.log_level,
            perf=config.backend.performance_logging,
        )
        self.db_reader_registrations = DBReaderRegistrations(
            db_path=config.backend.registration_sqlite_db,
            log_level=config.backend.log_level,
            perf=config.backend.performance_logging,
        )

        rpc_url = config.backend.rpc_api if config.backend.rpc_api else config.backend.rpc_shared
        rpc_cache = (
            config.backend.rpc_api_cache
            if config.backend.rpc_api_cache
            else config.backend.rpc_shared_cache
        )

        self.rpc = OxenRPC(
            self.log,
            rpc_url,
            rpc_cache,
        )
        self.loop_sleep_refresh_rate_seconds = rpc_cache if rpc_cache > 0 else 5

        self.data = DataManager(stale_time_seconds=config.backend.stale_time_seconds)

        self.allowed_contract_names = set()


app = App(config.backend.api_name if config.backend.api_name else __name__)


def get_and_refresh_allowed_contract_names():
    allowed_contract_names = set()
    for name in app.db_reader.get_smart_contract_names():
        allowed_contract_names.add(name)
    app.allowed_contract_names = allowed_contract_names
    return allowed_contract_names


app.url_map.converters["hex64"] = Hex64Converter
app.url_map.converters["eth_wallet"] = EthConverter


def get_median_operator_fee():
    # remove nodes that only have a single contributor
    nodes = [n for n in get_nodes_cached() if len(n.contributors) > 1]
    return statistics.median([n.operator_fee for n in nodes])


def get_network_info_uncached():
    network_info = app.db_reader.get_network_info()
    if network_info is None:
        return None
    network_info = dataclasses.asdict(network_info)
    network_info["median_operator_fee"] = get_median_operator_fee()
    return network_info


def json_response(vals):
    """
    Takes a dict, adds some general info fields to it, and jsonifies it for a flask route function
    return value.  The dict gets passed through `hexify` first to convert any bytes values to hex.
    """
    hexify(vals)
    network = app.data.get("network_info", getter=get_network_info_uncached)
    return flask.jsonify({**vals, "network": network, "t": time.time()})


@app.route("/info")
def get_network_info():
    return json_response({})


def get_nodes_cached():
    return app.data.get("nodes", getter=app.db_reader.get_nodes)


@app.route("/nodes")
def get_nodes():
    return json_response({"nodes": get_nodes_cached()})


"""
//////////////////////////////////////////////////////////////
//                                                          //
//                     Stake Endpoints                      //
//                                                          //
//////////////////////////////////////////////////////////////
"""


# TODO: might make sense to investigate storing contributor and operator addresses in the db as blobs and compare with bytes
@app.route("/stakes/<eth_wallet:eth_wal>")
@app.route("/nodes/<eth_wallet:eth_wal>")
def get_stakes_for_eth_address(eth_wal: str):
    try:
        if not eth_wal or not eth_utils.is_address(eth_wal):
            raise ValueError("Invalid wallet address")

        nodes = get_nodes_cached()

        related_nodes = []
        for node in nodes:
            if node.operator_address == eth_wal:
                related_nodes.append(node)
            elif node.contributors is not None:
                for contributor in node.contributors:
                    if contributor.address == eth_wal:
                        related_nodes.append(node)

        return json_response({"stakes": related_nodes})

    except ValueError as e:
        app.logger.error(f"Exception: {e}")
        return flask.abort(400, e)
    except Exception as e:
        app.logger.error(f"Exception: {e}")
        return flask.abort(500, e)


@app.route("/stakes/<hex64:sn_pubkey>")
@app.route("/nodes/<hex64:sn_pubkey>")
def get_stakes_for_sn_pubkey(sn_pubkey: bytes):
    try:
        nodes = get_nodes_cached()
        related_nodes = [node for node in nodes if node.pubkey_ed25519 == sn_pubkey]
        return json_response({"stakes": related_nodes})

    except Exception as e:
        app.logger.error(f"Exception: {e}")
        return flask.abort(500, e)


"""
//////////////////////////////////////////////////////////////
//                                                          //
//                   Contract Endpoints                     //
//                                                          //
//////////////////////////////////////////////////////////////
"""


def get_cached_allowed_contract_names():
    return app.data.get(
        "allowed_contract_names",
        getter=get_and_refresh_allowed_contract_names,
        ttl=config.backend.stale_time_seconds_contract_abis,
    )


@app.route("/contract/names")
def get_abi_names():
    return json_response({"names": list(get_cached_allowed_contract_names())})


@app.route("/contract/abis")
def get_abis():
    return json_response(
        {"abis": app.data.get("abis", getter=app.db_reader.get_smart_contract_abis)}
    )


@app.route("/contract/addresses")
def get_contract_addresses():
    return json_response(
        {"addresses": app.data.get("addresses", getter=app.db_reader.get_smart_contract_addresses)}
    )

@app.route("/contract/addresses/core")
def get_contract_addresses_core():
    return json_response(
        {"addresses": app.data.get("addresses_core", getter=app.db_reader.get_smart_contract_addresses_core)}
    )

@app.route("/contract/contribution")
def get_open_contract_details():
    return json_response(
        {"contracts": app.data.get("contracts", getter=app.db_reader.get_contribution_contracts)}
    )


@app.route("/contract/abi/<contract_name>")
def get_abi(contract_name: str):
    if contract_name not in get_cached_allowed_contract_names():
        return flask.abort(404, f"Contract {contract_name} not found")

    return json_response(
        {
            "contract": app.data.get(
                "abi", getter=app.db_reader.get_smart_contract_abi, getter_args=contract_name
            )
        }
    )


@app.route("/contract/address/<contract_name>")
def get_contract_address(contract_name: str):
    if contract_name not in get_cached_allowed_contract_names():
        return flask.abort(404, f"Contract {contract_name} not found")

    return json_response(
        {
            "address": app.data.get(
                "address",
                getter=app.db_reader.get_smart_contract_address,
                getter_args=contract_name,
            )
        }
    )


"""
//////////////////////////////////////////////////////////////
//                                                          //
//                    Event Endpoints                       //
//                                                          //
//////////////////////////////////////////////////////////////
"""

def get_events_handler(count_limit=500, skip=0):
    limit = min(count_limit, 500)
    events, limit, skip, total = app.data.get("events-{}-{}".format(count_limit,skip), getter=app.db_reader.get_arbitrum_events, getter_args=[limit, skip], ttl=10)
    pagination = {"limit": limit, "skip": skip, "total": total}

    return {"events": events, "pagination": pagination}

@app.route("/events/<int:count>/<int:skip>")
def get_events(count: int, skip: int):
    return json_response(get_events_handler(count, skip))

@app.route("/arbitrum-info")
def get_arbitrum_info():
    return json_response({"info": app.data.get("arbitrum-info", getter=app.db_reader.get_arbitrum_info)})

@app.route("/stake-events/<int:contract_id>")
def get_stake_events(contract_id: int):
    if contract_id < 0:
        return flask.abort(400, "Invalid contract ID")

    return json_response({"events": app.data.get("stake-events-{}".format(contract_id), getter=app.db_reader.get_arbitrum_events_for_stake_contrat_id, getter_args=contract_id)})

"""
//////////////////////////////////////////////////////////////
//                                                          //
//                     Exit Endpoints                       //
//                                                          //
//////////////////////////////////////////////////////////////
"""


def handle_get_exit_and_liquidation(ed25519_pubkey: bytes, liquidate: bool):
    try:
        response = app.rpc.bls_exit_liquidation_request(ed25519_pubkey, liquidate).get()
        if response is None:
            return flask.abort(504)  # Gateway timeout
        if "status" in response:
            response.pop("status")
        result = json_response({"result": response})
        return result
    except TimeoutError:
        return flask.abort(408)  # Request timeout


@app.route("/exit/<hex64:ed25519_pubkey>")
def get_exit(ed25519_pubkey: bytes):
    return handle_get_exit_and_liquidation(ed25519_pubkey, liquidate=False)


@app.route("/liquidation/<hex64:ed25519_pubkey>")
def get_liquidation(ed25519_pubkey: bytes):
    return handle_get_exit_and_liquidation(ed25519_pubkey, liquidate=True)


@app.route("/exit_liquidation_list")
def get_exit_liquidation_list():
    # TODO: add exit list management to main.py and main database and implement db_reader.get_exitable_nodes
    # return json_response(
    #     {"result": app.data.get("exit_liquidation_list", getter=app.db_reader.get_exitable_nodes)}
    # )
    return json_response({"result": []})


"""
//////////////////////////////////////////////////////////////
//                                                          //
//                   Rewards Endpoints                      //
//                                                          //
//////////////////////////////////////////////////////////////
"""

def get_rewards_signature_uncached(eth_wal: str):
    if not eth_wal or not eth_utils.is_address(eth_wal):
        raise ValueError("Invalid wallet address")
    response = app.rpc.bls_rewards_request(eth_utils.to_checksum_address(eth_wal)).get()
    if response is None:
        raise TimeoutError("Failed to get rewards signature")
    return response

@app.route("/rewards/<eth_wallet:eth_wal>", methods=["GET", "POST"])
def get_rewards(eth_wal: str):
    if flask.request.method == "GET":
        # We cache all rewards info for all wallets so we don't need to multiple reads in a short period of time
        rewards_info = app.data.get(f"rewards_info", getter=app.db_reader.get_rewards_info)
        return json_response({"rewards": rewards_info.get(eth_wal, 0)})

    if flask.request.method == "POST":
        try:
            response = app.data.get(f"rewards-sig-{eth_wal}", getter=get_rewards_signature_uncached, getter_args=eth_wal)
            if "status" in response:
                response.pop("status")
            if "address" in response:
                response.pop("address")
            return json_response({"rewards": response})
        except ValueError as e:
            return flask.abort(400, str(e))
        except TimeoutError:
            return flask.abort(408)  # Request timeout

    return flask.abort(405)  # Method not allowed


"""
//////////////////////////////////////////////////////////////
//                                                          //
//                 Registration Endpoints                   //
//                                                          //
//////////////////////////////////////////////////////////////
"""


@app.route("/registrations/<eth_wallet:operator>")
def operator_registrations(operator: str):
    """
    Retrieves stored registration(s) for the given 'operator'.

    This returns an array in the "registrations" field containing as many registrations as are
    currently stored for the given operator wallet, sorted from most to least recently submitted.

    Fields are the same as the version of this endpoint that takes a SN pubkey.

    Returns the JSON response with the 'registrations' for the given 'operator'.
    """

    operator_bytes = bytes.fromhex(operator[2:])

    return json_response(
        {
            "registrations": app.data.get(
                f"op-{operator_bytes}",
                getter=app.db_reader_registrations.get_registrations_for_operator,
                getter_args=operator_bytes,
            )
        }
    )


@app.route("/registrations/<hex64:sn_pubkey>")
def sn_pubkey_registrations(sn_pubkey: bytes) -> flask.Response:
    """
    Retrieves stored registration(s) for the given service node pubkey.

    This returns an array in the "registrations" field containing either one or two registration
    info dicts: a solo registration (if known) and a multi-contributor contract registration (if
    known).  These are sorted by timestamp of when the registration was last received/updated.

    Fields in each dict:
    - "operator": the operator address.
    - "contract": the contract address, for "type": "contract" and omitted for "type": "solo".
    - "pubkey_ed25519": the primary SN pubkey, in hex.
    - "pubkey_bls": the SN BLS pubkey, in hex.
    - "sig_ed25519": the SN pubkey signed registration signature.
    - "sig_bls": the SN BLS pubkey signed registration signature.
    - "timestamp": the unix timestamp when this registration was received (or last updated)

    Returns the JSON response with the 'registrations' for the given 'sn_pubkey'.
    """
    result = json_response(
        {
            "registrations": app.data.get(
                f"sn-{sn_pubkey}",
                getter=app.db_reader_registrations.get_registrations_by_pubkey,
                getter_args=sn_pubkey,
            )
        }
    )
    return result

def bootstrap():
    get_and_refresh_allowed_contract_names()


bootstrap()
