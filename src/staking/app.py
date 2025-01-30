#!/usr/bin/env python3
import dataclasses
import statistics
import flask
import eth_utils
from eth_typing import ChecksumAddress
from uwsgidecorators import timer
from werkzeug.exceptions import GatewayTimeout

from src.staking.dataclasses import ArbitrumInfo
from src.staking.read import DBReaderStaking
from ..oxen.rpc import OxenRPC
from ..registration.read import DBReaderRegistrations
from ..util.flask_utils import FlaskApp, json_response
from ..util.parse import Hex64Converter, EthConverter, eth_format


class App(FlaskApp):
    def __init__(self, config):
        name = config.backend.registration_api_name if config.backend.registration_api_name else __name__
        super().__init__(name, enable_perf=config.backend.performance_logging,
                         log_level=config.backend.log_level, log_level_generic=config.backend.log_level_generic,
                         cache_stale_time_seconds=config.backend.stale_time_seconds)

        self.db_reader = DBReaderStaking(
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
            logger=self.log,
            rpc_url=rpc_url,
            cache_seconds=rpc_cache,
            usage_tracking=config.backend.rpc_api_usage_logging,
        )

        self.allowed_contract_names = set()


def create_app(config) -> App:
    app = App(config)

    def get_and_refresh_allowed_contract_names():
        allowed_contract_names = set()
        for name in app.db_reader.get_smart_contract_names():
            allowed_contract_names.add(name)
        app.allowed_contract_names = allowed_contract_names
        return allowed_contract_names

    app.url_map.converters["hex64"] = Hex64Converter
    app.url_map.converters["eth_wallet"] = EthConverter

    def get_median_operator_fee_uncached():
        # remove nodes that only have a single contributor
        nodes = [n for n in get_nodes_cached() if len(n.contributors) > 1]
        return statistics.median([n.operator_fee for n in nodes]) if len(nodes) > 0 else 0

    def get_median_operator_fee_cached():
        return app.cache.get("median_operator_fee", getter=get_median_operator_fee_uncached, ttl=3600)

    def get_network_info_uncached() -> tuple[dict | None, ArbitrumInfo]:
        network_info = app.db_reader.get_network_info()
        arbitrum_info = app.db_reader.get_arbitrum_info()
        if network_info is None:
            return None, arbitrum_info
        network_info = dataclasses.asdict(network_info)
        network_info["median_operator_fee"] = get_median_operator_fee_cached()
        return network_info, arbitrum_info

    def get_next_block_timestamp_est():
        network_info, arbitrum_info = get_network_info_cached()
        return network_info["pulse_target_timestamp"]

    def get_network_info_cached():
        return app.cache.get("network_info", getter=get_network_info_uncached, ttl=1)

    def json_res(vals, include_network_info=True):
        if include_network_info:
            network_info, arbitrum_info = get_network_info_cached()
            network_info["l2_height"] = arbitrum_info.block
            network_info["l2_height_timestamp"] = arbitrum_info.timestamp
            vals["network"] = network_info

        return json_response(vals)

    @app.route("/info")
    def get_network_info():
        return json_res({})

    def get_nodes_cached():
        return app.cache.get("nodes", getter=app.db_reader.get_nodes)

    @app.route("/nodes")
    def route_get_nodes():
        return json_res({"nodes": get_nodes_cached()})

    def get_nodes_bls_keys_cached():
        return app.cache.get("contract_node_bls_keys_added",
                             getter=app.db_reader.get_service_node_rewards_contract_id_bls_key_map)

    @app.route("/nodes/bls")
    def route_get_nodes_bls_keys():
        return json_res({"bls_keys": get_nodes_bls_keys_cached()})

    """
    //////////////////////////////////////////////////////////////
    //                                                          //
    //                     Stake Endpoints                      //
    //                                                          //
    //////////////////////////////////////////////////////////////
    """

    def get_related_stakes_for_eth_address_uncached(address: ChecksumAddress):
        nodes = get_nodes_cached()

        related_nodes = []
        for node in nodes:
            if eth_format(node.operator_address) == address:
                related_nodes.append(node)
            elif node.contributors is not None:
                for contributor in node.contributors:
                    if eth_format(contributor.address) == address:
                        related_nodes.append(node)

        return related_nodes

    def get_related_stakes_for_eth_address_cached(address: ChecksumAddress):
        return app.cache.get("related-stakes-{}".format(address), getter=get_related_stakes_for_eth_address_uncached,
                             getter_args=address)

    # TODO: might make sense to investigate storing contributor and operator addresses in the db as blobs and compare with bytes
    @app.route("/stakes/<eth_wallet:eth_wal>")
    @app.route("/nodes/<eth_wallet:eth_wal>")
    def route_get_stakes_for_eth_address(eth_wal: str):
        try:
            address = eth_format(eth_wal)
            return json_res({"stakes": get_related_stakes_for_eth_address_cached(address),
                             "contracts": get_related_contribution_contracts_for_eth_address_cached(address),
                             "added_bls_keys": get_nodes_bls_keys_cached()})

        except ValueError as e:
            app.logger.error(f"Exception: {e}")
            return flask.abort(400, e)
        except Exception as e:
            app.logger.error(f"Exception: {e}")
            app.logger.exception(e)
            return flask.abort(500, e)

    @app.route("/stakes/<hex64:sn_pubkey>")
    @app.route("/nodes/<hex64:sn_pubkey>")
    def route_get_stakes_for_sn_pubkey(sn_pubkey: bytes):
        try:
            nodes = get_nodes_cached()
            related_nodes = [node for node in nodes if node.pubkey_ed25519 == sn_pubkey]
            return json_res({"stakes": related_nodes})

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
        return app.cache.get(
            "allowed_contract_names",
            getter=get_and_refresh_allowed_contract_names,
            ttl=config.backend.stale_time_seconds_contract_abis
        )

    @app.route("/contract/names")
    def route_get_abi_names():
        return json_res({"names": list(get_cached_allowed_contract_names())})

    @app.route("/contract/abis")
    def route_get_abis():
        return json_res(
            {"abis": app.cache.get("abis_all", getter=app.db_reader.get_smart_contract_abis,
                                   ttl=config.backend.stale_time_seconds_contract_abis)}
        )

    @app.route("/contract/addresses")
    def get_contract_addresses():
        return json_res(
            {"addresses": app.cache.get("addresses_all", getter=app.db_reader.get_smart_contract_addresses)}
        )

    @app.route("/contract/addresses/core")
    def get_contract_addresses_core():
        return json_res(
            {"addresses": app.cache.get("addresses_core", getter=app.db_reader.get_smart_contract_addresses_core,
                                        ttl=config.backend.stale_time_seconds_contract_abis)}
        )

    def get_contribution_contracts_cached():
        return app.cache.get("contracts", getter=app.db_reader.get_contribution_contracts, ttl=2)

    @app.route("/contract/contribution")
    def get_open_contract_details():
        return json_res(
            {"contracts": get_contribution_contracts_cached(), "added_bls_keys": get_nodes_bls_keys_cached()}
        )

    def get_contribution_contracts_for_sn_pubkey_uncached(sn_pubkey: bytes):
        cached_contracts = app.db_reader.get_contribution_contracts()
        contracts = [contract for contract in cached_contracts if contract.service_node_pubkey == sn_pubkey]
        return contracts

    @app.route("/contract/contribution/<hex64:sn_pubkey>")
    def get_contribution_contract_for_sn_pubkey_cached(sn_pubkey: bytes):
        key = sn_pubkey.hex()
        return json_res(
            {"contracts": app.cache.get("contract-sn-{}".format(key),
                                        getter=get_contribution_contracts_for_sn_pubkey_uncached, getter_args=key,
                                        ttl=2)}
        )

    def get_related_contribution_contracts_for_eth_address_uncached(eth_wal: str):
        contracts = get_contribution_contracts_cached()

        related_contracts = []
        for contract in contracts:
            if contract.operator_address == eth_wal:
                related_contracts.append(contract)
            elif contract.contributors is not None:
                for contributor in contract.contributors:
                    if contributor.address == eth_wal:
                        related_contracts.append(contract)
        return related_contracts

    def get_related_contribution_contracts_for_eth_address_cached(eth_wal: str):
        return app.cache.get("related-contracts-{}".format(eth_wal),
                             getter=get_related_contribution_contracts_for_eth_address_uncached, getter_args=eth_wal)

    @app.route("/contract/contribution/<eth_wallet:eth_wal>")
    def get_contribution_contracts_for_wallet(eth_wal: str):
        try:
            if not eth_wal or not eth_utils.is_address(eth_wal):
                raise ValueError("Invalid wallet address")

            return json_res({"contracts": get_related_contribution_contracts_for_eth_address_cached(eth_wal)})

        except ValueError as e:
            app.logger.error(f"Exception: {e}")
            return flask.abort(400, e)
        except Exception as e:
            app.logger.error(f"Exception: {e}")
            return flask.abort(500, e)

    @app.route("/contract/abi/<contract_name>")
    def get_abi(contract_name: str):
        if contract_name not in get_cached_allowed_contract_names():
            return flask.abort(404, f"Contract {contract_name} not found")

        return json_res(
            {
                "contract": app.cache.get(
                    "abi-{}".format(contract_name), getter=app.db_reader.get_smart_contract_abi,
                    getter_args=contract_name,
                    ttl=config.backend.stale_time_seconds_contract_abis
                )
            }
        )

    @app.route("/contract/address/<contract_name>")
    def get_contract_address(contract_name: str):
        if contract_name not in get_cached_allowed_contract_names():
            return flask.abort(404, f"Contract {contract_name} not found")

        return json_res(
            {
                "address": app.cache.get(
                    "address-{}".format(contract_name),
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
        events, limit, skip, total = app.cache.get("events-{}-{}".format(count_limit, skip),
                                                   getter=app.db_reader.get_arbitrum_events_page,
                                                   getter_args=[limit, skip],
                                                   ttl=10)
        pagination = {"limit": limit, "skip": skip, "total": total}

        return {"events": events, "pagination": pagination}

    @app.route("/events/<int:count>/<int:skip>")
    def get_events(count: int, skip: int):
        return json_res(get_events_handler(count, skip))

    def get_arbitrum_info_uncached():
        return app.db_reader.get_arbitrum_info()

    @app.route("/arbitrum-info")
    def get_arbitrum_info():
        return json_res({"info": app.cache.get("arbitrum-info", getter=get_arbitrum_info_uncached)})

    @app.route("/stake-events/<int:contract_id>")
    def get_stake_events(contract_id: int):
        if contract_id < 0:
            return flask.abort(400, "Invalid contract ID")

        return json_res({"events": app.cache.get("stake-events-{}".format(contract_id),
                                                 getter=app.db_reader.get_arbitrum_events_for_stake_contrat_id,
                                                 getter_args=contract_id)})

    """
    //////////////////////////////////////////////////////////////
    //                                                          //
    //                     Exit Endpoints                       //
    //                                                          //
    //////////////////////////////////////////////////////////////
    """

    def handle_get_exit_and_liquidation(params: [bytes, bool]):
        ed25519_pubkey, liquidate = params[0], params[1]
        if ed25519_pubkey not in get_exitable_ed25519_keys_cached():
            return flask.abort(404, f"No exit available for {ed25519_pubkey.hex()}")

        response = app.rpc.bls_exit_liquidation_request(ed25519_pubkey, liquidate).get()
        if response is None:
            raise GatewayTimeout("Failed to get exit signature")
        if "status" in response:
            response.pop("status")

        return json_res({"result": response})

    def handle_get_exit_and_liquidation_cached(params: [bytes, bool]):
        try:
            return app.cache.get(f"exit-{params[0]}-{params[1]}", getter=handle_get_exit_and_liquidation,
                                 getter_args=params,
                                 invalidate_timestamp=get_next_block_timestamp_est())
        except GatewayTimeout as e:
            app.logger.error(f"Exception: {e}")
            return flask.abort(504)  # Gateway timeout
        except TimeoutError:
            return flask.abort(408)  # Request timeout
        except Exception as e:
            app.logger.error(f"Exception: {e}")
            return flask.abort(500, e)

    @app.route("/exit/<hex64:ed25519_pubkey>")
    def route_get_exit(ed25519_pubkey: bytes):
        return handle_get_exit_and_liquidation_cached([ed25519_pubkey, False])

    @app.route("/liquidation/<hex64:ed25519_pubkey>")
    def route_get_liquidation(ed25519_pubkey: bytes):
        return handle_get_exit_and_liquidation_cached([ed25519_pubkey, True])

    def get_exit_liquidation_list_uncached():
        return app.rpc.bls_exit_liquidation_list().get()

    def get_exit_liquidation_list_cached():
        return app.cache.get("exit_liquidation_list", getter=get_exit_liquidation_list_uncached,
                             invalidate_timestamp=get_next_block_timestamp_est())

    @app.route("/exit_liquidation_list")
    def route_get_exit_liquidation_list():
        return json_res(
            {"result": get_exit_liquidation_list_cached()}
        )

    def get_exitable_ed25519_keys_uncached():
        return set([bytes.fromhex(x.get("service_node_pubkey")) for x in get_exit_liquidation_list_cached()])

    def get_exitable_ed25519_keys_cached():
        return app.cache.get("exitable_ed25519_keys", getter=get_exitable_ed25519_keys_uncached,
                             invalidate_timestamp=get_next_block_timestamp_est())

    """
    //////////////////////////////////////////////////////////////
    //                                                          //
    //                   Rewards Endpoints                      //
    //                                                          //
    //////////////////////////////////////////////////////////////
    """

    def get_rewards_signature_uncached(eth_wal: str):
        address = eth_format(eth_wal)
        response = app.rpc.bls_rewards_request(address).get()
        if response is None:
            raise TimeoutError("Failed to get rewards signature")

        response.pop("status") if "status" in response else None
        response.pop("address") if "address" in response else None

        return response

    def get_rewards_info_cached():
        # We cache all rewards info for all wallets so we don't need to multiple reads in a short period of time
        return app.cache.get(f"rewards_info", getter=app.db_reader.get_rewards_info,
                             invalidate_timestamp=get_next_block_timestamp_est())

    def get_rewards_info_for_address_cached(eth_wal: str):
        address = eth_format(eth_wal)
        rewards_info = get_rewards_info_cached()
        return rewards_info.get(address, 0)

    def get_rewards_info_response(eth_wal: str):
        return json_res({"rewards": get_rewards_info_for_address_cached(eth_wal)})

    def get_rewards_signature_response(eth_wal: str):
        try:
            rewards = get_rewards_info_for_address_cached(eth_wal)
            if rewards == 0:
                return flask.abort(404, f"No rewards available for {eth_wal}")

            return json_res(
                {"rewards": app.cache.get(f"rewards-sig-{eth_wal}", getter=get_rewards_signature_uncached,
                                          getter_args=eth_wal,
                                          invalidate_timestamp=get_next_block_timestamp_est())})
        except ValueError as e:
            return flask.abort(400, str(e))

    @app.route("/rewards/<eth_wallet:eth_wal>", methods=["GET", "POST"])
    def get_rewards(eth_wal: str):
        if flask.request.method == "GET":
            return app.cache.get(f"rewards-info-response-{eth_wal}", getter=get_rewards_info_response,
                                 getter_args=eth_wal,
                                 invalidate_timestamp=get_next_block_timestamp_est())

        if flask.request.method == "POST":
            try:
                return app.cache.get(f"rewards-sig-response-{eth_wal}", getter=get_rewards_signature_response,
                                     getter_args=eth_wal, invalidate_timestamp=get_next_block_timestamp_est())
            except TimeoutError:
                # We don't want to cache a 408 response
                return flask.abort(408)

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

        return json_res(
            {
                "registrations": app.cache.get(
                    f"registrations-op-{operator_bytes}",
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
        result = json_res(
            {
                "registrations": app.cache.get(
                    f"registration-sn-{sn_pubkey}",
                    getter=app.db_reader_registrations.get_registrations_by_pubkey,
                    getter_args=sn_pubkey,
                )
            }
        )
        return result

    """
    //////////////////////////////////////////////////////////////
    //                                                          //
    //                     Token Endpoints                      //
    //                                                          //
    //////////////////////////////////////////////////////////////
    """

    def get_token_info_uncached():
        net_info, arb_info = get_network_info_uncached()
        staking_requirement = net_info.get("staking_requirement")
        contract_address = app.db_reader.get_smart_contract_address("Token")
        contract_address = eth_utils.to_checksum_address(contract_address) if contract_address is not None else None

        return {
            "staking_requirement": staking_requirement,
            "staking_reward_pool": arb_info.balance_reward_rate_pool,
            "contract_address": contract_address,
        }

    @app.route("/token")
    def route_get_token_info():
        return json_res({"token": app.cache.get("token_info", getter=get_token_info_uncached)},
                        include_network_info=False)

    """
    //////////////////////////////////////////////////////////////
    //                                                          //
    //                    Network Endpoints                     //
    //                                                          //
    //////////////////////////////////////////////////////////////
    """

    def get_network_info_basic_uncached():
        network_info = app.db_reader.get_network_info()
        return {
            "network_size": network_info.network_size,
        }

    @app.route("/network")
    def route_get_network_info():
        return json_res({"network": app.cache.get("network_info_basic", getter=get_network_info_basic_uncached)})

    """
    //////////////////////////////////////////////////////////////
    //                                                          //
    //                        Bootstap                          //
    //                                                          //
    //////////////////////////////////////////////////////////////
    """

    get_and_refresh_allowed_contract_names()

    """
    //////////////////////////////////////////////////////////////
    //                                                          //
    //                         Timers                           //
    //                                                          //
    //////////////////////////////////////////////////////////////
    """

    if config.backend.rpc_api_usage_logging:
        def log_rpc_usage(signum):
            app.rpc.usage_tracker.log_usage(" For signum {}".format(signum))
            app.rpc.usage_tracker.write_failure_reasons_to_file(f"rpc-usage-failure-reasons-{signum}.txt")

        @timer(config.backend.rpc_api_usage_logging_interval, target="worker1")
        def log_rpc_usage_w1(signum):
            log_rpc_usage(signum)

        @timer(config.backend.rpc_api_usage_logging_interval, target="worker2")
        def log_rpc_usage_w2(signum):
            log_rpc_usage(signum)

        @timer(config.backend.rpc_api_usage_logging_interval, target="worker3")
        def log_rpc_usage_w3(signum):
            log_rpc_usage(signum)

        @timer(config.backend.rpc_api_usage_logging_interval, target="worker4")
        def log_rpc_usage_w4(signum):
            log_rpc_usage(signum)

    return app
