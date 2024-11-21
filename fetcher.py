#!/usr/bin/env python3
import json
import subprocess
import time

import config
from arbitrum import (
    get_service_node_rewards_contract_id_map,
    get_new_contribution_contracts,
    update_contribution_contract_details,
)
from config_validate import validate_config
from db.util import (
    assert_all_dict_values_are_within_sqlite_integer_range,
    is_db_initialized,
    init_db,
)
from db.read import DBReader
from db.write import DBWriter
from log import Log
from oxen.rpc import ServiceNode, OxenRPC, NetworkInfo
from util import format_seconds
from log.time_keeper import TimeKeeper
from web3client.abi_manager import ABIManager
from web3client.client import Web3Client
from web3client.contracts.reward_rate_pool import RewardRatePoolInterface
from web3client.contracts.service_node_contribution import (
    ServiceNodeContributionInterface,
)
from web3client.contracts.service_node_contribution_factory import (
    ServiceNodeContributionFactory,
)
from web3client.contracts.service_node_rewards import ServiceNodeRewardsInterface
from web3client.contracts.sent import SENTInterface
from oxen.omq import omq_connection


class App:
    def __init__(self, name):
        super().__init__()
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
        validate_config(config)
        if not is_db_initialized(config.backend.sqlite_db):
            self.log.info(
                "Initializing database {} with schema {}".format(
                    config.backend.sqlite_db, config.backend.sqlite_schema
                )
            )
            init_db(config.backend.sqlite_db, config.backend.sqlite_schema)

        self.db_reader = DBReader(
            db_path=config.backend.sqlite_db,
            log_level=config.backend.log_level,
            perf=config.backend.performance_logging,
        )
        self.db_writer = DBWriter(
            db_path=config.backend.sqlite_db,
            log_level=config.backend.log_level,
            perf=config.backend.performance_logging,
        )

        rpc_url = (
            config.backend.rpc_fetcher if config.backend.rpc_fetcher else config.backend.rpc_shared
        )
        rpc_cache = (
            config.backend.rpc_fetcher_cache
            if config.backend.rpc_fetcher_cache
            else config.backend.rpc_shared_cache
        )

        self.rpc = OxenRPC(
            self.log,
            rpc_url,
            rpc_cache,
        )
        self.loop_sleep_refresh_rate_seconds = rpc_cache if rpc_cache > 0 else 5

        self.arbitrum_details_last_updated = 0

        self.web3_client = Web3Client(
            provider_url=config.backend.web3_provider_url,
            caller_address=config.backend.web3_caller_address,
            private_key=config.backend.web3_private_key,
            logger=self.log,
            abi_manager=ABIManager(db_writer=self.db_writer, abi_dir=config.backend.abi_dir),
        )

        self.token_contract = SENTInterface(
            web3_client=self.web3_client, contract_address=config.backend.addr_sent
        )
        self.service_node_rewards = ServiceNodeRewardsInterface(
            web3_client=self.web3_client,
            contract_address=config.backend.addr_sn_rewards,
            scanner_safety_blocks=config.backend.arbitrum_rescan_safety_blocks,
        )
        self.reward_rate_pool = RewardRatePoolInterface(
            web3_client=self.web3_client, contract_address=config.backend.addr_reward_rate_pool
        )
        self.service_node_contribution_factory = ServiceNodeContributionFactory(
            web3_client=self.web3_client,
            contract_address=config.backend.addr_sn_contrib_factory,
            scanner_safety_blocks=config.backend.arbitrum_rescan_safety_blocks,
        )
        self.service_node_contribution = ServiceNodeContributionInterface(
            web3_client=self.web3_client,
            contract_address=config.backend.addr_sn_contrib,
        )
        self.service_node_contribution_multi: dict[str, ServiceNodeContributionInterface] = {}

        self.time_keeper = TimeKeeper(
            logger=Log("time_keeper").logger,
            perf=config.backend.performance_logging,
            max_events=config.backend.max_time_keeper_events,
        )

        self.bootstrap()

    def bootstrap(self):
        self.log.info("Bootstrapping")
        self.log.perf.start("bootstrap")

        contribution_contract_addresses = self.db_reader.get_contribution_contract_addresses()
        self.log.debug(
            "Found {} contribution contract addresses".format(len(contribution_contract_addresses))
        )

        contract_details = [
            {"address": interface.contract_address, "name": interface.abi_name}
            for interface in [
                self.service_node_contribution,
                self.reward_rate_pool,
                self.service_node_rewards,
                self.token_contract,
                self.service_node_contribution_factory,
            ]
        ]
        for address in contribution_contract_addresses:
            self.service_node_contribution_multi[address] = ServiceNodeContributionInterface(
                self.web3_client,
                address,
            )
            contract_details.append(
                {"address": address, "name": ServiceNodeContributionInterface.abi_name}
            )

        self.db_writer.write_smart_contract_details_to_db(contract_details)

        self.log.perf.end("bootstrap")

    def run(self):
        t1_event_loop_exception_count = 0
        t2_event_loop_exception_count = 0
        try:
            while True:
                try:
                    self.log.perf.start("loop")
                    network = self.rpc.get_network_info_from_network()

                    network_last_fetched_height = (
                        self.db_reader.get_last_fetched_network_block_height()
                    )
                    network_last_commited_height = (
                        self.db_reader.get_last_commited_network_block_height()
                    )
                    self.log.debug(
                        "Last fetched height: {}, Immutable height: {}, Commited height {}, Current height: {}, next block timestamp: {}, ".format(
                            network_last_fetched_height,
                            network.immutable_block_height,
                            network_last_commited_height,
                            network.block_height,
                            network.pulse_target_timestamp,
                        )
                    )

                    if (
                        time.time() - self.arbitrum_details_last_updated
                        > config.backend.refresh_rate_seconds_arbitrum
                    ):
                        self.time_keeper.add("arb_update")
                        self.update_arbitrum_details()
                        self.time_keeper.end("arb_update")

                    if network.immutable_block_height > network_last_commited_height:
                        self.time_keeper.add("db_migrate")
                        self.db_writer.write_nodes_to_main_db(network.immutable_block_height)
                        self.time_keeper.end("db_migrate")

                    if (network.block_height - 1) > network_last_fetched_height:
                        self.time_keeper.add("net_update")
                        self.update_network_details_and_nodes(network)
                        self.time_keeper.end("net_update")

                    self.log.perf.end("loop")
                    self.time_keeper.log_time_keeper()

                    now = time.time()
                    arb_next_update = (
                        self.arbitrum_details_last_updated
                        + config.backend.refresh_rate_seconds_arbitrum
                    )

                    sleep_seconds = max(
                        self.loop_sleep_refresh_rate_seconds,
                        min(
                            arb_next_update,
                            network.pulse_target_timestamp,
                        )
                        - now,
                    )

                    self.log.debug(
                        "Sleeping for {}s ({}) (Target Event: {})".format(
                            format_seconds(sleep_seconds),
                            format_seconds(now + sleep_seconds, 0),
                            (
                                "network_update"
                                if sleep_seconds == network.pulse_target_timestamp
                                else (
                                    "arb_update"
                                    if sleep_seconds == arb_next_update - now
                                    else "min_refresh"
                                )
                            ),
                        )
                    )

                    time.sleep(sleep_seconds)

                except Exception as e:
                    self.log.error("Error in event loop task")
                    self.log.exception(e)

                    t1_event_loop_exception_count += 1

                    if t2_event_loop_exception_count > 3:
                        self.log.warning(
                            "Too many t2 event loop exceptions, sleeping for 5 minutes before continuing"
                        )
                        t2_event_loop_exception_count = 0
                        time.sleep(300)
                    elif t1_event_loop_exception_count > 10:
                        self.log.warning(
                            "Too many t1 event loop exceptions, sleeping for 30 seconds before continuing"
                        )
                        t2_event_loop_exception_count += 1
                        t1_event_loop_exception_count = 0
                        time.sleep(30)
                    else:
                        self.log.error("Sleeping for 1 second before continuing")
                        time.sleep(1)

        except KeyboardInterrupt:
            self.log.info("Application exiting...")

    def update_network_details_and_nodes(
        self,
        network: NetworkInfo,
    ):
        self.log.perf.start("update_service_node_list")
        self.log.info("Update service node list task start")
        parsed_nodes, contributor_stake_map, current_height = self.fetch_service_node_list()

        self.db_writer.write_nodes_to_staging_db(
            current_height, parsed_nodes, contributor_stake_map
        )

        self.db_writer.write_network_info_to_db(network)
        self.log.info("Scheduled task finish")
        self.log.perf.end("scheduled_task")

    def fetch_service_node_list(self):
        self.log.perf.start("fetch_service_node_list")
        current_height = None
        parsed_nodes = []
        contributions = []

        try:
            res = self.rpc.get_service_nodes().get()
            current_height = res.get("height")
            self.log.debug("Fetched service node list at height {}".format(current_height))

            nodes: list[ServiceNode] = res.get("service_node_states")
            self.log.debug("Fetched {} service nodes".format(len(nodes)))

            # TODO: remove once contract_id is available via rpc.get_service_nodes
            contract_id_map = get_service_node_rewards_contract_id_map(self.service_node_rewards)

            for node in nodes:
                pubkey_bls = None
                try:
                    # TODO: remove once contract_id is available via rpc.get_service_nodes vv
                    pubkey_bls = node.get("pubkey_bls")
                    contract_id = contract_id_map.get(pubkey_bls)
                    if contract_id is None:
                        self.log.warning(
                            "Contract ID not found for node with BLS pubkey: {}".format(pubkey_bls)
                        )
                    node["contract_id"] = contract_id
                    # TODO: remove once contract_id is available via rpc.get_service_nodes ^^

                    # contract_id = node.get("contract  _id")
                    # assert contract_id is not None

                    # Remove some fields that might appear if field:all is passed to the rpc
                    if "portions_for_operator" in node:
                        del node["portions_for_operator"]

                    # Convert some ints to strings to avoid overflowing the sqlite integer type
                    node["swarm_id"] = str(node["swarm_id"])

                    lokinet_version = node.get("lokinet_version", None)
                    node["lokinet_version"] = (
                        json.dumps(lokinet_version) if lokinet_version is not None else None
                    )

                    pulse_votes = node.get("pulse_votes", None)
                    node["pulse_votes"] = (
                        json.dumps(pulse_votes) if pulse_votes is not None else None
                    )

                    service_node_version = node.get("service_node_version", None)
                    node["service_node_version"] = (
                        json.dumps(service_node_version)
                        if service_node_version is not None
                        else None
                    )

                    storage_server_version = node.get("storage_server_version", None)
                    node["storage_server_version"] = (
                        json.dumps(storage_server_version)
                        if storage_server_version is not None
                        else None
                    )

                    assert node["contract_id"] is not None

                    assert_all_dict_values_are_within_sqlite_integer_range(node)

                    for contributor in node.get("contributors", []):
                        contributor_address = None
                        try:
                            amount = contributor.get("amount")
                            assert amount is not None

                            contributor_address = contributor.get("address")
                            assert contributor_address is not None

                            contributions.append(
                                {
                                    "address": contributor_address,
                                    "beneficiary": contributor.get("beneficiary"),
                                    "contract_id": contract_id,
                                    "amount": amount,
                                }
                            )

                        except Exception as e:
                            self.log.error(
                                "Error processing contributor {} for node {}".format(
                                    contributor_address,
                                    pubkey_bls,
                                )
                            )
                            self.log.exception(e)
                            continue

                    parsed_nodes.append(node)

                except Exception as e:
                    self.log.error("Error processing node {}".format(pubkey_bls))
                    self.log.exception(e)
                    continue

        except Exception as e:
            self.log.error("Error fetching and parsing service node list")
            self.log.exception(e)
        finally:
            self.log.perf.end("update_service_node_list")
            return parsed_nodes, contributions, current_height

    def update_arbitrum_details(self):
        try:
            self.log.perf.start("update_arbitrum_details")
            self.log.info("Update arbitrum details task start")

            last_event_block_height = self.db_reader.get_last_fetched_arbitrum_event_block_height()
            end_block = self.web3_client.web3.eth.block_number - 1

            new_contribution_contracts, new_contribution_events = get_new_contribution_contracts(
                self.web3_client,
                self.log,
                self.service_node_contribution_factory,
                last_event_block_height,
                end_block,
            )

            new_contracts = []
            for contract in new_contribution_contracts:
                self.service_node_contribution_multi[contract.contract_address] = contract
                new_contracts.append(
                    {"address": contract.contract_address, "name": contract.abi_name}
                )

            self.db_writer.write_smart_contract_details_to_db(new_contracts)

            contract_details_list, contributions_list = update_contribution_contract_details(
                self.web3_client, self.log, list(self.service_node_contribution_multi.values())
            )

            self.db_writer.write_contribution_contracts_to_db(
                contract_details_list, contributions_list
            )

            service_node_rewards_events = self.service_node_rewards.event_scanner.run(
                last_block=last_event_block_height,
                end_block=end_block,
            )

            service_node_rewards_events.extend(new_contribution_events)

            self.db_writer.write_arbitrum_events_to_db(service_node_rewards_events)

            self.arbitrum_details_last_updated = time.time()
            self.log.perf.end("update_arbitrum_details")

        except Exception as e:
            self.log.error("Error fetching and parsing arbitrum details")
            self.log.exception(e)


app = App(config.backend.fetcher_name if config.backend.fetcher_name else __name__)
app.run()
