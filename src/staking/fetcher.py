#!/usr/bin/env python3
import json
import subprocess
import time

from ..config_validate import validate_log_config, validate_contract_addresses, validate_web3_client, validate_oxen_rpc
from ..staking.arbitrum import (
    get_new_contribution_contracts,
    update_contribution_contract_details, populate_events_with_main_arg,
)
from .. import config
from ..staking.dataclasses import RewardsInfo, DBNodeExit
from ..db.util import (
    assert_all_dict_values_are_within_sqlite_integer_range,
    is_db_initialized,
    init_db,
)
from ..staking.read import DBReaderStaking
from ..staking.write import DBWriterStaking
from ..log import Log
from ..oxen.rpc import ServiceNode, OxenRPC, NetworkInfo
from ..util import format_seconds
from ..log.time_keeper import TimeKeeper
from ..util.parse import parse_bls_pubkey
from ..web3client.abi_manager import ABIManager
from ..web3client.client import Web3Client
from ..web3client.contracts.reward_rate_pool import RewardRatePoolInterface
from ..web3client.contracts.service_node_contribution import (
    ServiceNodeContributionInterface,
)
from ..web3client.contracts.service_node_contribution_factory import (
    ServiceNodeContributionFactory,
)
from ..web3client.contracts.service_node_rewards import ServiceNodeRewardsInterface
from ..web3client.contracts.token import TokenInterface


class App:
    def __init__(self, name, run_once_as_script=False):
        super().__init__()
        log = Log(name, enable_perf=config.backend.performance_logging)
        log.set_level(config.backend.log_level)
        self.log = log.logger
        self.run_once_as_script = run_once_as_script

        validate_log_config(config.backend)
        validate_contract_addresses(config.backend)

        self.arbitrum_updates_disabled = config.backend.ws_enabled
        if self.arbitrum_updates_disabled:
            self.log.warning(
                "Arbitrum updates are disabled because ws_enabled is set to True, the separate websocket fetcher should be used instead")
        else:
            self.log.info("Arbitrum updates are enabled")
            validate_web3_client(config)

        validate_oxen_rpc(config.backend)

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

        if not is_db_initialized(config.backend.sqlite_db):
            self.log.info(
                "Initializing database {} with schema {}".format(
                    config.backend.sqlite_db, config.backend.sqlite_schema
                )
            )
            init_db(config.backend.sqlite_db, config.backend.sqlite_schema)

        self.db_reader = DBReaderStaking(
            db_path=config.backend.sqlite_db,
            log_level=config.backend.log_level,
            perf=config.backend.performance_logging,
        )
        self.db_writer = DBWriterStaking(
            db_path=config.backend.sqlite_db,
            log_level=config.backend.log_level,
            perf=config.backend.performance_logging,
        )

        rpc_url = config.backend.rpc_shared
        rpc_cache = (
            config.backend.rpc_fetcher_cache
            if config.backend.rpc_fetcher_cache
            else config.backend.rpc_shared_cache
        )

        self.rpc = OxenRPC(
            logger=self.log,
            rpc_url=rpc_url,
            cache_seconds=rpc_cache,
            usage_tracking=config.backend.rpc_fetcher_usage_logging,
        )

        self.loop_sleep_refresh_rate_seconds = rpc_cache if rpc_cache > 0 else 1

        self.arbitrum_details_next_update_time = 0

        self.web3_client = Web3Client(
            provider_urls=config.backend.web3_provider_urls,
            caller_address=config.backend.web3_caller_address,
            private_key=config.backend.web3_private_key,
            logger=self.log,
            abi_manager=ABIManager(db_writer=self.db_writer, abi_dir=config.backend.abi_dir),
        )

        self.log.info(
            f"Using contract addresses:\n Token: {config.backend.addr_token}\n SN Rewards: {config.backend.addr_sn_rewards}\n Reward Rate Pool: {config.backend.addr_reward_rate_pool}\n SN Contribution Factory: {config.backend.addr_sn_contrib_factory}")

        self.token_contract = TokenInterface(
            web3_client=self.web3_client, contract_address=config.backend.addr_token
        )
        self.service_node_rewards = ServiceNodeRewardsInterface(
            web3_client=self.web3_client,
            contract_address=config.backend.addr_sn_rewards,
            scanner_safety_blocks=config.backend.arbitrum_rescan_safety_blocks,
            scan_start_chunk_size=config.backend.arbitrum_scan_start_chunk_size
        )
        self.reward_rate_pool = RewardRatePoolInterface(
            web3_client=self.web3_client, contract_address=config.backend.addr_reward_rate_pool
        )
        self.service_node_contribution_factory = ServiceNodeContributionFactory(
            web3_client=self.web3_client,
            contract_address=config.backend.addr_sn_contrib_factory,
            scanner_safety_blocks=config.backend.arbitrum_rescan_safety_blocks,
            scan_start_chunk_size=config.backend.arbitrum_scan_start_chunk_size
        )
        self.service_node_contribution = ServiceNodeContributionInterface(
            web3_client=self.web3_client,
            contract_address=config.backend.addr_sn_contrib,
        )
        self.service_node_contribution_multi: dict[str, ServiceNodeContributionInterface] = {}

        self.time_keeper = TimeKeeper(
            logger=Log("time_keeper").logger,
            max_events=config.backend.max_time_keeper_events,
        )

        self.last_new_sn_event = 0
        self.contract_id_map = {}

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

                    if not self.arbitrum_updates_disabled and time.time() >= self.arbitrum_details_next_update_time:
                        self.time_keeper.add("arb_update")
                        self.update_arbitrum_details()
                        self.time_keeper.end("arb_update")

                    if network.immutable_block_height > network_last_commited_height:
                        self.time_keeper.add("db_migrate_and_update_exit_list")
                        self.db_writer.write_nodes_to_main_db(network.immutable_block_height)
                        self.update_exit_list()
                        self.time_keeper.end("db_migrate_and_update_exit_list")

                    if (network.block_height - 1) > network_last_fetched_height:
                        self.time_keeper.add("net_update")
                        self.update_network_details_and_nodes(network)
                        self.time_keeper.end("net_update")

                    self.log.perf.end("loop")
                    self.time_keeper.log_time_keeper()
                    self.rpc.usage_tracker.log_usage()
                    if config.backend.write_rpc_fail_reasons_to_file:
                        self.rpc.usage_tracker.write_failure_reasons_to_file(f"rpc-usage-failure-reasons-fetcher.txt")

                    now = time.time()

                    sleep_seconds = max(
                        self.loop_sleep_refresh_rate_seconds,
                        (network.pulse_target_timestamp - 5 if self.arbitrum_updates_disabled else
                         min(self.arbitrum_details_next_update_time, network.pulse_target_timestamp)
                         ) - now,
                    )

                    self.log.info(
                        "Sleeping for {}s ({}) (Target Event: {})".format(
                            format_seconds(sleep_seconds),
                            format_seconds(now + sleep_seconds, 0),
                            (
                                "network_update"
                                if sleep_seconds == network.pulse_target_timestamp - 5 - now
                                else (
                                    "arb_update"
                                    if sleep_seconds == self.arbitrum_details_next_update_time - now
                                    else "min_refresh"
                                )
                            ),
                        )
                    )

                    if self.run_once_as_script:
                        self.log.info("run_once_as_script is True, exiting...")
                        return

                    time.sleep(sleep_seconds)

                except Exception as e:
                    self.log.error("Error in event loop task")
                    self.log.exception(e)

                    t1_event_loop_exception_count += 1

                    if t2_event_loop_exception_count > 3:
                        self.log.warning(
                            "Too many t2 event loop exceptions, sleeping for 2 minutes before continuing"
                        )
                        t2_event_loop_exception_count = 0
                        time.sleep(120)
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
        self.log.info("Update service node list task start")
        parsed_nodes, contributor_stake_map, current_height, node_count, active_node_count = self.fetch_service_node_list()

        self.db_writer.write_nodes_to_staging_db(
            current_height, parsed_nodes, contributor_stake_map
        )

        self.db_writer.write_network_info_to_db(network=network, node_count=node_count,
                                                active_node_count=active_node_count)

        rewards_info = self.get_rewards_info()
        self.db_writer.write_rewards_info_to_db(rewards_info)

        self.log.info("Scheduled task finish")

    def fetch_service_node_list(self):
        self.log.perf.start("fetch_service_node_list")
        current_height = None
        parsed_nodes = []
        contributions = []
        active_node_count = 0

        try:
            res = self.rpc.get_service_nodes().get()
            current_height = res.get("height")
            self.log.debug("Fetched service node list at height {}".format(current_height))

            nodes: list[ServiceNode] = res.get("service_node_states")
            self.log.debug("Fetched {} service nodes".format(len(nodes)))

            new_sn_events = self.db_reader.get_arbitrum_events_by_name("NewServiceNodeV2",
                                                                       from_block=self.last_new_sn_event + 1)
            if len(new_sn_events) == 0:
                self.log.warning("No new service node events found, waiting for new events")
                return

            for event in new_sn_events:
                self.contract_id_map[parse_bls_pubkey(event.args["pubkey"])] = event.args["serviceNodeID"]
                if event.block > self.last_new_sn_event:
                    self.last_new_sn_event = event.block

            for node in nodes:
                pubkey_bls = None
                try:
                    if node.get("active"):
                        active_node_count += 1

                    pubkey_bls = node.get("pubkey_bls")
                    contract_id = self.contract_id_map.get(pubkey_bls)
                    node["contract_id"] = contract_id

                    if node["contract_id"] is None:
                        self.log.warning(
                            "Contract ID not found for node with BLS pubkey: {}".format(pubkey_bls)
                        )
                    assert node["contract_id"] is not None

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
                            self.log.error(f"Error processing contributor {contributor_address} for node {pubkey_bls}")
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
            return parsed_nodes, contributions, current_height, len(parsed_nodes), active_node_count

    def update_exit_list(self):
        self.log.perf.start("update_exit_list")
        self.log.info("Update exit list task start")
        exit_liquidation_list = self.rpc.bls_exit_liquidation_list().get()

        if exit_liquidation_list is None:
            self.log.warning("bls_exit_liquidation_list is None, fetching exit list failed")
            return

        exit_events = []
        for entry in exit_liquidation_list:

            pubkey_bls = entry.get("info").get("bls_public_key")
            if pubkey_bls is None:
                self.log.warning(f"info.bls_public_key is None for bls_exit_liquidation_list entry: {entry}")
                continue

            exit_type = entry.get("type")
            exit_events.append(
                DBNodeExit(
                    pubkey_bls=pubkey_bls,
                    deregistration_height=entry.get("height") if exit_type == "deregister" else None,
                    exit_type=exit_type,
                    liquidation_height=entry.get("liquidation_height"),
                )
            )

        self.log.debug("Processed {} exit events".format(len(exit_events)))
        self.db_writer.write_exit_list_to_db(exit_events)
        self.log.info("Update exit list task finish")
        self.log.perf.end("update_exit_list")

    def get_rewards_info(self):
        self.log.perf.start("update_rewards_details")
        self.log.debug("Update rewards details task start")
        rewards_info = []
        try:
            # Get the accrued rewards values for each wallet
            accrued_rewards_json = self.rpc.get_accrued_rewards().get()

            assert accrued_rewards_json is not None, "Accrued rewards request failed"
            assert accrued_rewards_json["status"] == "OK", "Accrued rewards request failed {}".format(
                accrued_rewards_json)
            assert "balances" in accrued_rewards_json, "Accrued rewards request failed, 'balances' key was missing: {}".format(
                accrued_rewards_json)

            # Populate (Binary ETH wallet address -> accrued_rewards) table
            for address_hex, rewards in accrued_rewards_json.get("balances").items():
                # Ignore non-ethereum addresses (e.g. left oxen rewards, not relevant)
                address = address_hex if address_hex.startswith("0x") else "0x" + address_hex
                if len(address) != 42:
                    self.log.warning("Invalid address {}".format(address))
                    continue

                rewards_info.append(RewardsInfo(address, rewards))

        except Exception as e:
            self.log.error("Error fetching and parsing rewards details")
            self.log.exception(e)
        finally:
            self.log.perf.end("update_rewards_details")
            return rewards_info

    def update_arbitrum_details(self):
        try:
            self.log.perf.start("update_arbitrum_details")
            self.log.info("Update arbitrum details task start")

            last_event_block_height = self.db_reader.get_last_fetched_arbitrum_event_block_height()
            current_block = self.web3_client.web3.eth.block_number
            end_block = current_block - 1

            service_node_rewards_balance = self.token_contract.balance_of(self.service_node_rewards.contract_address)
            reward_rate_pool_balance = self.token_contract.balance_of(self.reward_rate_pool.contract_address)
            self.log.debug("Arbitrum info: service node rewards balance {}, reward rate pool balance {}".format(
                service_node_rewards_balance, reward_rate_pool_balance))
            self.db_writer.write_arbitrum_info_to_db(current_block, service_node_rewards_balance,
                                                     reward_rate_pool_balance)

            new_contribution_contracts, new_contribution_events = get_new_contribution_contracts(
                self.web3_client,
                self.log,
                self.service_node_contribution_factory,
                last_event_block_height,
                end_block,
            )

            # Writing contract details to db

            new_contracts = []
            for contract in new_contribution_contracts:
                self.service_node_contribution_multi[contract.contract_address] = contract
                new_contracts.append(
                    {"address": contract.contract_address, "name": contract.abi_name}
                )

            self.db_writer.write_smart_contract_details_to_db(new_contracts)

            # NOTE: Writes events to db BEFORE writing contribution contracts to db so the events are available for the "recent_add_node_events_since_last_update" function

            events = self.service_node_rewards.event_scanner.run(
                last_block=last_event_block_height,
                end_block=end_block,
            )

            events.extend(new_contribution_events)
            populate_events_with_main_arg(events)

            self.db_writer.write_arbitrum_events_to_db(events)

            # Writing contribution contract details to db (if there are any)

            contrib_contract_list = list(self.service_node_contribution_multi.values())
            if len(contrib_contract_list) > 0:
                contract_details_list, contributions_list = update_contribution_contract_details(
                    self.web3_client, self.log, contrib_contract_list
                )

                self.db_writer.write_contribution_contracts_to_db(contract_details_list, contributions_list)
            else:
                self.log.info("No contribution contracts to write to db")

            self.arbitrum_details_next_update_time = time.time() + config.backend.refresh_rate_seconds_arbitrum
            self.log.perf.end("update_arbitrum_details")

        except Exception as e:
            self.log.error("Error fetching and parsing arbitrum details")
            self.log.exception(e)
