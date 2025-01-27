#!/usr/bin/env python3
import eth_utils
from util.flask_utils import FlaskApp, FlaskReqLimiter, json_response
from werkzeug.middleware.proxy_fix import ProxyFix
from db.util import is_db_initialized, init_db
from registration.read import DBReaderRegistrations
from registration.validation import check_reg_keys_sigs
from registration.write import DBWriterRegistrations
from util.parse import (
    parse_query_params,
    byte_decoder,
    EthConverter,
    hexify,
    Hex64Converter,
    raw_eth_addr,
)


class App(FlaskApp):
    def __init__(self, config):
        name = config.backend.registration_api_name if config.backend.registration_api_name else __name__
        super().__init__(name, enable_perf=config.backend.performance_logging,
                         log_level=config.backend.log_level,
                         cache_stale_time_seconds=config.backend.stale_time_seconds)

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

        self.allowed_contract_names = set()
        self.log.info(
            f"IP Rate limit: {config.backend.registration_api_rate_limit} per {config.backend.registration_api_rate_limit_period} seconds")


def create_app(config) -> App:
    app = App(config)

    # Enables more reliable proxy pass through for rate limiting
    app.wsgi_app = ProxyFix(app.wsgi_app)
    app.req_limiter = FlaskReqLimiter(max_reqs_per_sec=config.backend.registration_api_rate_limit,
                                      rate_limit_period=config.backend.registration_api_rate_limit_period)

    @app.before_request
    def rate_limit():
        return app.req_limiter.rate_limit()

    app.url_map.converters["hex64"] = Hex64Converter
    app.url_map.converters["eth_wallet"] = EthConverter

    @app.route("/info")
    def get_network_info():
        return json_response()

    """
    //////////////////////////////////////////////////////////////
    //                                                          //
    //                 Registration Endpoints                   //
    //                                                          //
    //////////////////////////////////////////////////////////////
    """

    # NOTE: the /api prefix route here is to allow for local testing

    @app.route("/api/store/<hex64:sn_pubkey>", methods=["GET", "POST"])
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

    return app
