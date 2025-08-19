import sqlite3
from contextlib import closing

from ..db.read import DBReader
from .dataclasses import DBNode, DBContributionMain, DBNetworkInfo, DBContributionContract, \
    DBContributionContractContribution, SmartContractABI, ArbitrumInfo, VestingContract, RewardsInfo, \
    DailyRewardInfoNode
from ..db.util import sql_connect_in_read_mode
from ..log import Log
from ..util.parse import eth_format
from ..web3client.event_scanner import ProcessedEvent


class DBReaderStaking:
    def __init__(self, db_path: str, log_level: int, perf: bool = False):
        self.log = Log("db_reader", log_level, enable_perf=perf).logger
        self.db_path = db_path

    def get_last_fetched_network_block_height(self) -> int:
        self.log.perf.start("get_last_fetched_network_block_height")
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
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
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
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
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute("SELECT * FROM network_info LIMIT 1")
                network_info = DBNetworkInfo(*cursor.fetchone())

                self.log.debug("Network Info: {}".format(network_info))
                self.log.perf.end("get_network_info")
                return network_info

    def get_last_fetched_arbitrum_event_block_height(self) -> int:
        self.log.perf.start("get_last_fetched_arbitrum_event_block_height")
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
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

    def get_contribution_contract_contributors(self, address:str):
        self.log.perf.start("get_contribution_contract_contributors")
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute("""SELECT * FROM contribution_contracts_contributions WHERE contract_address = ?""", (address,))
                contributors = [DBContributionContractContribution(*contribution) for contribution in cursor.fetchall()]
                self.log.debug("Contributors: {}".format(len(contributors)))
                self.log.perf.end("get_contribution_contract_contributors")
                return contributors

    def get_contribution_contracts(self):
        self.log.perf.start("get_contribution_contracts")
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute("""SELECT * FROM contribution_contracts""")
                contracts = cursor.fetchall()

                parsed_contracts = {}
                for contract in contracts:
                    contract_dict = DBContributionContract(*contract, contributors=[], events=[])
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
                return parsed_contracts

    def get_contribution_contracts_non_finalized(self):
        self.log.perf.start("get_contribution_contracts")
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute("""SELECT * FROM contribution_contracts""")
                contracts = cursor.fetchall()

                parsed_contracts = {}
                for contract in contracts:
                    contract_dict = DBContributionContract(*contract, contributors=[], events=[])
                    parsed_contracts[contract_dict.address] = contract_dict

                cursor.execute(
                    """
                    SELECT * FROM contribution_contracts_contributions where status < 3
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
                return parsed_contracts


    def get_contribution_contract_addresses(self):
        self.log.perf.start("get_contribution_contracts")
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
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
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                parsed_nodes = {}

                # TODO: investigate using a join or something less messy than two select * queries
                cursor.execute("""SELECT * FROM service_nodes_main""")

                for node in cursor.fetchall():
                    node_dict = DBNode(*node, contributors=[], events=[])
                    parsed_nodes[node_dict.contract_id] = node_dict

                # We want to sort by fetched_block_height in ascending order so later updates overwrite earlier ones
                cursor.execute(
                    """SELECT * FROM service_nodes_staging ORDER BY fetched_block_height ASC"""
                )

                for node in cursor.fetchall():
                    node_dict = DBNode(*node, exit_type=None, deregistration_height=None, liquidation_height=None, contributors=[], events=[])
                    existing_node = parsed_nodes.get(node_dict.contract_id)
                    if existing_node is not None:
                        existing_node.exit_type = node_dict.exit_type
                        existing_node.deregistration_height = node_dict.deregistration_height
                        existing_node.liquidation_height = node_dict.liquidation_height
                    parsed_nodes[node_dict.contract_id] = node_dict


                cursor.execute("""SELECT * from service_nodes_contributions_main""")

                db_contributions_main = [DBContributionMain(*contribution) for contribution in cursor.fetchall()]

                # We want to sort by fetched_block_height in ascending order so later updates overwrite earlier ones
                cursor.execute(
                    """SELECT * from service_nodes_contributions_staging ORDER BY fetched_block_height ASC"""
                )

                db_contributions_staging = [DBContributionMain(*contribution) for contribution in cursor.fetchall()]

                parsed_contributions = {}
                for contribution_dict in db_contributions_main + db_contributions_staging:
                    # TODO: there has to be a better way to override the old data with new data
                    key = f"{contribution_dict.contract_id}{contribution_dict.address}"
                    parsed_contributions[key] = contribution_dict

                for contribution_dict in parsed_contributions.values():
                    parsed_nodes[contribution_dict.contract_id].contributors.append(
                        contribution_dict
                    )

                contract_ids = list(parsed_nodes.keys())

                placeholder= '?' # For SQLite. See DBAPI paramstyle.
                placeholders= ', '.join(placeholder for unused in contract_ids)
                query= 'SELECT * FROM arbitrum_events WHERE main_arg IN (%s) ORDER BY block DESC, log_index DESC' % placeholders
                cursor.execute(query, contract_ids)

                for event in cursor.fetchall():
                    processed_event = ProcessedEvent(*event)
                    try:
                        contract_id = int(processed_event.main_arg)
                        parsed_nodes[contract_id].events.append(processed_event)
                    except Exception as e:
                        self.log.error("Error processing event: {}".format(e))
                        continue

                nodes_list = list(parsed_nodes.values())

                self.log.debug("Parsed nodes: {}".format(len(nodes_list)))
                self.log.perf.end("get_nodes")
                return list(parsed_nodes.values())

    def get_contribution_addresses(self):
        self.log.perf.start("get_contribution_addresses")
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                addresses = set()
                cursor.execute("""SELECT address, beneficiary from service_nodes_contributions_main""")
                cursor.execute("""SELECT address, beneficiary from service_nodes_contributions_staging ORDER BY fetched_block_height ASC""")

                for address, beneficiary in cursor.fetchall():
                    addresses.add(address)
                    if beneficiary is not None:
                        addresses.add(beneficiary)

                self.log.debug("Contribution addresses: {}".format(len(addresses)))
                self.log.perf.end("get_contribution_addresses")
                return addresses

    def get_rewards_info(self):
        self.log.perf.start("get_rewards_info")
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute("SELECT * FROM rewards_info")
                rewards = [RewardsInfo(*info) for info in cursor.fetchall()]
                rewards_info = {info.address: info for info in rewards}
                self.log.debug("Rewards info: {}".format(len(rewards_info)))
                self.log.perf.end("get_rewards_info")
                return rewards_info

    def get_rewards_info_for_address(self, address: str):
        self.log.perf.start("get_rewards_info_for_address")
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute("SELECT * FROM rewards_info WHERE address = ?", (address,))
                if cursor.rowcount == 0:
                    return None
                info = RewardsInfo(*cursor.fetchone())
                self.log.debug("Rewards info: {}".format(info))
                self.log.perf.end("get_rewards_info_for_address")
                return info

    def get_daily_rewards_info_for_address(self, address: str, from_block: int = 0):
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute("SELECT block, lifetime_rewards, timestamp FROM daily_rewards_info WHERE address = ? AND block >= ?", (address, from_block))
                info = [DailyRewardInfoNode(*node) for node in cursor.fetchall()]
                return info

    def get_smart_contract_abis(self):
        self.log.perf.start("get_smart_contract_abis")
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
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
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
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
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
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
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
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
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
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
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
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

    def get_arbitrum_events(self, from_block = 0, names: list = None):
        self.log.perf.start("get_arbitrum_events")
        assert from_block >= 0, "from_block must be >= 0"
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                self.log.debug(f"Getting events from block {from_block} with names {names}")
                if names is None:
                    cursor.execute(
                        """
                        SELECT * FROM arbitrum_events WHERE block >= ?
                        """,
                        (from_block,),
                    )
                else:
                    placeholder= '?' # For SQLite. See DBAPI paramstyle.
                    placeholders= ', '.join(placeholder for unused in names)
                    query= 'SELECT * FROM arbitrum_events WHERE block >= ? AND name IN ({})'.format(placeholders)
                    cursor.execute(query, (from_block, *names))

                events = [ProcessedEvent(*event) for event in cursor.fetchall()]
                self.log.debug("Arbitrum events: {}".format(len(events)))
                self.log.perf.end("get_arbitrum_events")
                return events

    def get_arbitrum_events_by_name(self, name: str, from_block = 0):
        self.log.perf.start("get_arbitrum_events_by_name")
        assert from_block >= 0, "from_block must be >= 0"
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute(
                    """
                    SELECT * FROM arbitrum_events WHERE name = ?
                    """,
                    (name,),
                )
                events = [ProcessedEvent(*event) for event in cursor.fetchall()]
                self.log.debug("Arbitrum events: {}".format(len(events)))
                self.log.perf.end("get_arbitrum_events_by_name")
                return events

    def get_arbitrum_events_by_main_args_desc(self, main_args: list[str]):
        self.log.perf.start("get_arbitrum_events_by_main_arg")
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute(
                    """
                    SELECT * FROM arbitrum_events WHERE main_arg IN ({}) ORDER BY block DESC, log_index DESC
                    """.format(",".join(["?"] * len(main_args))),
                    (tuple(main_args)),
                )
                events = [ProcessedEvent(*event) for event in cursor.fetchall()]
                self.log.debug("Arbitrum events: {}".format(len(events)))
                self.log.perf.end("get_arbitrum_events_by_main_arg")
                return events


    def get_arbitrum_event_main_args_by_name(self, name: str, from_block = 0):
        self.log.perf.start("get_arbitrum_event_main_args_by_name")
        assert from_block >= 0, "from_block must be >= 0"
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute(
                    """
                    SELECT main_arg FROM arbitrum_events WHERE name = ? AND block >= ?
                    """,
                    (name, from_block),
                )
                events = cursor.fetchall()
                addresses = [event[0] for event in events]
                self.log.debug("Arbitrum Event Args: {}".format(len(addresses)))
                self.log.perf.end("get_arbitrum_event_main_args_by_name")
                return addresses


    def get_arbitrum_events_page(self, args=None):
        if args is None:
            args = [1000, 0]
        self.log.perf.start("get_arbitrum_events")
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                limit = args[0] if len(args) > 0 else 1000
                skip = args[1] if len(args) > 1 else 0

                cursor.execute(
                    """
                    SELECT * FROM arbitrum_events ORDER BY block DESC LIMIT ? OFFSET ?
                    """,
                    (limit, skip),
                )
                events = [ProcessedEvent(*event) for event in cursor.fetchall()]
                self.log.debug("Arbitrum events: {}".format(len(events)))
                self.log.perf.end("get_arbitrum_events")

                cursor.execute("SELECT COUNT(*) FROM arbitrum_events")
                total = cursor.fetchone()[0]

                return events, limit, skip, total

    def get_arbitrum_info(self):
        self.log.perf.start("get_arbitrum_info")
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute("SELECT * FROM arbitrum_info ORDER BY block DESC LIMIT 1")
                info = ArbitrumInfo(*cursor.fetchone())

                self.log.debug("Arbitrum info: {}".format(info))
                self.log.perf.end("get_arbitrum_info")
                return info

    def get_arbitrum_events_for_stake_contrat_id(self, contract_id: int):
        self.log.perf.start("get_events_for_stake_contrat_id")
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute(
                    """
                    SELECT * FROM arbitrum_events WHERE main_arg = ? ORDER BY block DESC
                    """,
                    (contract_id,),
                )
                events = [ProcessedEvent(*event) for event in cursor.fetchall()]
                self.log.debug("Arbitrum events: {}".format(len(events)))
                self.log.perf.end("get_events_for_stake_contrat_id")
                return events

    def get_vesting_contracts(self) -> list[VestingContract]:
        self.log.perf.start("get_vesting_contracts")
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute(
                    """
                    SELECT * FROM vesting_contracts
                    """
                )
                contracts = [VestingContract(*contract) for contract in cursor.fetchall()]
                self.log.debug("Vesting contracts: {}".format(len(contracts)))
                self.log.perf.end("get_vesting_contracts")
                return contracts

    def has_vesting_contracts(self) -> bool:
        self.log.perf.start("has_vesting_contracts")
        with closing(sql_connect_in_read_mode(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute(
                    """
                    SELECT COUNT(*) FROM vesting_contracts
                    """
                )
                count = cursor.fetchone()[0]
                self.log.debug("Vesting contracts: {}".format(count))
                self.log.perf.end("has_vesting_contracts")
                return count > 0
