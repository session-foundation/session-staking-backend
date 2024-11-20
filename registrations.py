#!/usr/bin/env python3
import flask
import time

import eth_utils
import subprocess
import config

from db.util import is_db_initialized, init_db
from log import Log
from registration.read import DBReaderRegistrations
from registration.validation import check_reg_keys_sigs
from registration.write import DBWriterRegistrations
from util.data import DataManager
from util.parse import (
    parse_query_params,
    byte_decoder,
    EthConverter,
    hexify,
    Hex64Converter,
    raw_eth_addr,
)


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

        if not is_db_initialized(config.backend.registration_sqlite_db):
            self.log.info(
                "Initializing database {} with schema {}".format(
                    config.backend.registration_sqlite_db, config.backend.registration_sqlite_schema
                )
            )
            init_db(
                config.backend.registration_sqlite_db, config.backend.registration_sqlite_schema
            )

        self.db_reader = DBReaderRegistrations(
            db_path=config.backend.registration_sqlite_db,
            log_level=config.backend.log_level,
            perf=config.backend.performance_logging,
        )
        self.db_writer = DBWriterRegistrations(
            db_path=config.backend.registration_sqlite_db,
            log_level=config.backend.log_level,
            perf=config.backend.performance_logging,
        )

        self.data = DataManager(stale_time_seconds=config.backend.stale_time_seconds)

        self.allowed_contract_names = set()


app = App(
    config.backend.registration_api_name if config.backend.registration_api_name else __name__
)


app.url_map.converters["hex64"] = Hex64Converter
app.url_map.converters["eth_wallet"] = EthConverter


def json_response(vals):
    """
    Takes a dict, adds some general info fields to it, and jsonifies it for a flask route function
    return value.  The dict gets passed through `hexify` first to convert any bytes values to hex.
    """
    hexify(vals)
    return flask.jsonify({**vals, "t": time.time()})


@app.route("/info")
def get_network_info():
    return json_response({})


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
                getter=app.db_reader.get_registrations_for_operator,
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
                getter=app.db_reader.get_registrations_by_pubkey,
                getter_args=sn_pubkey,
            )
        }
    )
    return result


@app.route("/registrations/<hex64:sn_pubkey>", methods=["POST"])
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
    address is passed in the "c" parameter.

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
        return json_response({"error": f"Invalid registration: {e}"})

    app.db_writer.write_registration_to_db(params)

    params["operator"] = eth_utils.to_checksum_address(params["operator"])
    params["contract"] = (
        eth_utils.to_checksum_address(params["contract"]) if "contract" in params else None
    )

    return json_response({"success": True, "registration": params})
