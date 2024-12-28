import sqlite3
from contextlib import closing

import eth_utils

from db.dataclasses import DBNode, DBContributionMain, DBNetworkInfo, DBContributionContract, \
    DBContributionContractContribution, SmartContractABI, ArbitrumEvent, ArbitrumInfo, RewardsInfo
from log import Log
from web3client.event_scanner import ProcessedEvent


class DBReader:
    def __init__(self, db_path: str, log_level: int, perf: bool = False):
        self.db_path = db_path
        self.log = Log("db_reader", log_level, enable_perf=perf).logger

    def get_last_fetched_network_block_height(self) -> int:
        self.log.perf.start("get_last_fetched_network_block_height")
        with closing(sqlite3.connect(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute("SELECT MAX(fetched_block_height) FROM service_nodes_staging")
                (fetched_block_height,) = cursor.fetchone()
                self.log.debug(
                    "get_last_fetched_network_block_height result: {}".format(fetched_block_height)
                )
                self.log.perf.end("get_last_fetched_network_block_height")
                return fetched_block_height if fetched_block_height is not None else 0

    def get_last_commited_network_block_height(self) -> int:
        self.log.perf.start("get_last_commited_network_block_height")
        with closing(sqlite3.connect(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute("SELECT MAX(fetched_block_height) FROM service_nodes_main")
                (commited_block_height,) = cursor.fetchone()
                self.log.debug(
                    "get_last_commited_network_block_height result: {}".format(
                        commited_block_height
                    )
                )
                self.log.perf.end("get_last_commited_network_block_height")
                return commited_block_height if commited_block_height is not None else 0

    def get_network_info(self):
        self.log.perf.start("get_network_info")
        with closing(sqlite3.connect(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute("SELECT * FROM network_info LIMIT 1")
                network_info = DBNetworkInfo(*cursor.fetchone())

                self.log.debug("Network Info: {}".format(network_info))
                self.log.perf.end("get_network_info")
                return network_info

    def get_last_fetched_arbitrum_event_block_height(self) -> int:
        self.log.perf.start("get_last_fetched_arbitrum_event_block_height")
        with closing(sqlite3.connect(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute("SELECT MAX(block) FROM arbitrum_events")
                (fetched_block_height,) = cursor.fetchone()
                self.log.debug(
                    "get_last_fetched_arbitrum_event_block_height result: {}".format(
                        fetched_block_height
                    )
                )
                self.log.perf.end("get_last_fetched_arbitrum_event_block_height")
                return fetched_block_height if fetched_block_height is not None else 0

    def get_contribution_contracts(self):
        self.log.perf.start("get_contribution_contracts")
        with closing(sqlite3.connect(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute("""SELECT * FROM contribution_contracts""")
                contracts = cursor.fetchall()

                parsed_contracts = {}
                for contract in contracts:
                    contract_dict = DBContributionContract(*contract, contributors=[])
                    parsed_contracts[contract_dict.address] = contract_dict

                cursor.execute(
                    """
                    SELECT * FROM contribution_contracts_contributions
                    """
                )
                contributions = cursor.fetchall()
                for contribution in contributions:
                    contribution_dict = DBContributionContractContribution(*contribution)
                    parsed_contracts[contribution_dict.contract_address].contributors.append(
                        contribution_dict
                    )

                self.log.debug("Parsed contribution contracts: {}".format(len(parsed_contracts)))
                self.log.perf.end("get_contribution_contracts")
                return list(parsed_contracts.values())

    def get_contribution_contract_addresses(self):
        self.log.perf.start("get_contribution_contracts")
        with closing(sqlite3.connect(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute(
                    """
                    SELECT address FROM contribution_contracts 
                    """
                )
                addresses = cursor.fetchall()
                self.log.debug("Contract addresses: {}".format(len(addresses)))
                self.log.perf.end("get_contribution_contracts")
                return [address[0] for address in addresses]

    def get_nodes(self):
        self.log.perf.start("get_nodes")
        with closing(sqlite3.connect(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                # TODO: investigate using a join or something less messy than two select * queries
                cursor.execute("""SELECT * FROM service_nodes_main""")
                # We want to sort by fetched_block_height in ascending order so later updates overwrite earlier ones
                cursor.execute(
                    """SELECT * FROM service_nodes_staging ORDER BY fetched_block_height ASC"""
                )

                parsed_nodes = {}
                for node in cursor.fetchall():
                    node_dict = DBNode(*node, contributors=[])
                    parsed_nodes[node_dict.contract_id] = node_dict

                cursor.execute("""SELECT * from service_nodes_contributions_main""")
                # We want to sort by fetched_block_height in ascending order so later updates overwrite earlier ones
                cursor.execute(
                    """SELECT * from service_nodes_contributions_staging ORDER BY fetched_block_height ASC"""
                )

                parsed_contributions = {}
                for contribution in cursor.fetchall():
                    contribution_dict = DBContributionMain(*contribution)
                    # TODO: there has to be a better way to override the old data with new data
                    key = f"{contribution_dict.contract_id}{contribution_dict.address}"
                    parsed_contributions[key] = contribution_dict

                for contribution_dict in parsed_contributions.values():
                    parsed_nodes[contribution_dict.contract_id].contributors.append(
                        contribution_dict
                    )

                self.log.debug("Parsed nodes: {}".format(len(parsed_nodes)))
                self.log.perf.end("get_nodes")
                return list(parsed_nodes.values())

    def get_rewards_info(self):
        self.log.perf.start("get_rewards_info")
        with closing(sqlite3.connect(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute("SELECT * FROM rewards_info")
                rewards_info = {
                    address: rewards
                    for address, rewards in cursor.fetchall()
                }
                self.log.debug("Rewards info: {}".format(len(rewards_info)))
                self.log.perf.end("get_rewards_info")
                return rewards_info

    def get_smart_contract_abis(self):
        self.log.perf.start("get_smart_contract_abis")
        with closing(sqlite3.connect(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute(
                    """
                    SELECT * FROM smart_contract_abis
                    """
                )
                abis = [SmartContractABI(*abi) for abi in cursor.fetchall()]
                self.log.debug("Smart contract abis: {}".format(len(abis)))
                self.log.perf.end("get_smart_contract_abis")
                return abis

    def get_smart_contract_abi(self, name: str):
        self.log.perf.start("get_smart_contract_abi")
        with closing(sqlite3.connect(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute(
                    """
                    SELECT * FROM smart_contract_abis WHERE name = ?
                    """,
                    (name,),
                )
                abi = SmartContractABI(*cursor.fetchone())
                self.log.debug("Smart contract abi: {}".format(abi))
                self.log.perf.end("get_smart_contract_abi")
                return abi

    def get_smart_contract_names(self) -> list[str]:
        self.log.perf.start("get_smart_contract_names")
        with closing(sqlite3.connect(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute(
                    """
                    SELECT name FROM smart_contract_abis
                    """
                )
                names = [name[0] for name in cursor.fetchall()]
                self.log.debug("Smart contract names: {}".format(len(names)))
                self.log.perf.end("get_smart_contract_names")
                return names

    def get_smart_contract_addresses(self):
        self.log.perf.start("get_smart_contract_addresses")
        with closing(sqlite3.connect(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute(
                    """
                    SELECT address, name FROM smart_contracts
                    """
                )
                addresses = [
                    {"address": address, "name": name} for address, name in cursor.fetchall()
                ]
                self.log.debug("Smart contract addresses: {}".format(len(addresses)))
                self.log.perf.end("get_smart_contract_addresses")
                return addresses

    def get_smart_contract_addresses_core(self):
        self.log.perf.start("get_smart_contract_addresses_core")
        with closing(sqlite3.connect(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute(
                    """
                    SELECT address, name FROM smart_contracts WHERE name IN ('ServiceNodeRewards', 'ServiceNodeContributionFactory', 'ServiceNodeRewards')
                    """
                )
                addresses = [
                    {"address": address, "name": name} for address, name in cursor.fetchall()
                ]
                self.log.debug("Smart contract addresses: {}".format(len(addresses)))
                self.log.perf.end("get_smart_contract_addresses_core")
                return addresses

    def get_smart_contract_address(self, name: str):
        self.log.perf.start("get_smart_contract_address")
        with closing(sqlite3.connect(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute(
                    """
                    SELECT address FROM smart_contracts WHERE name = ?
                    """,
                    (name,),
                )
                address = cursor.fetchone()
                self.log.debug("Smart contract address: {}".format(address))
                self.log.perf.end("get_smart_contract_address")
                return address[0]

    def get_arbitrum_events(self, args=None):
        if args is None:
            args = [1000, 0]
        self.log.perf.start("get_arbitrum_events")
        with closing(sqlite3.connect(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                limit = args[0]
                skip = args[1]
                cursor.execute(
                    """
                    SELECT * FROM arbitrum_events ORDER BY block DESC LIMIT ? OFFSET ?
                    """,
                    (limit, skip),
                )
                events = [ArbitrumEvent(*event) for event in cursor.fetchall()]
                self.log.debug("Arbitrum events: {}".format(len(events)))
                self.log.perf.end("get_arbitrum_events")

                cursor.execute("SELECT COUNT(*) FROM arbitrum_events")
                total = cursor.fetchone()[0]

                return events, limit, skip, total

    def get_arbitrum_info(self):
        self.log.perf.start("get_arbitrum_info")
        with closing(sqlite3.connect(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute("SELECT * FROM arbitrum_info ORDER BY block DESC LIMIT 1")
                info = ArbitrumInfo(*cursor.fetchone())

                self.log.debug("Arbitrum info: {}".format(info))
                self.log.perf.end("get_arbitrum_info")
                return info

    def get_arbitrum_events_for_stake_contrat_id(self, contract_id: int):
        self.log.perf.start("get_events_for_stake_contrat_id")
        with closing(sqlite3.connect(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute(
                    """
                    SELECT * FROM arbitrum_events WHERE main_arg = ? ORDER BY block DESC
                    """,
                    (contract_id,),
                )
                events = [ArbitrumEvent(*event) for event in cursor.fetchall()]
                self.log.debug("Arbitrum events: {}".format(len(events)))
                self.log.perf.end("get_events_for_stake_contrat_id")
                return events

