import sqlite3
from contextlib import closing

from ..db.read import DBReader
from ..staking.dataclasses import DBNode, DBContributionMain, DBNetworkInfo, DBContributionContract, \
    DBContributionContractContribution, SmartContractABI, ArbitrumInfo
from ..util.parse import eth_format
from ..web3client.event_scanner import ProcessedEvent


class DBReaderStaking(DBReader):
    def __init__(self, db_path: str, log_level: int, perf: bool = False):
        super().__init__(db_path, log_level, perf)

    def get_last_fetched_network_block_height(self) -> int:
        self.log.perf.start("get_last_fetched_network_block_height")
        with closing(self.connect()) as connection:
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
        with closing(self.connect()) as connection:
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
        with closing(sqlite3.connect(self.db_path, uri=True)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute("SELECT * FROM network_info LIMIT 1")
                network_info = DBNetworkInfo(*cursor.fetchone())

                self.log.debug("Network Info: {}".format(network_info))
                self.log.perf.end("get_network_info")
                return network_info

    def get_last_fetched_arbitrum_event_block_height(self) -> int:
        self.log.perf.start("get_last_fetched_arbitrum_event_block_height")
        with closing(self.connect()) as connection:
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
        with closing(self.connect()) as connection:
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
        with closing(self.connect()) as connection:
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
        with closing(self.connect()) as connection:
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
                query= 'SELECT * FROM arbitrum_events WHERE main_arg IN (%s) ORDER BY block DESC' % placeholders
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

    def get_rewards_info(self):
        self.log.perf.start("get_rewards_info")
        with closing(self.connect()) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute("SELECT * FROM rewards_info")
                rewards_info = {
                    eth_format(address_hex): rewards
                    for address_hex, rewards in cursor.fetchall()
                }
                self.log.debug("Rewards info: {}".format(len(rewards_info)))
                self.log.perf.end("get_rewards_info")
                return rewards_info

    def get_smart_contract_abis(self):
        self.log.perf.start("get_smart_contract_abis")
        with closing(self.connect()) as connection:
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
        with closing(self.connect()) as connection:
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
        with closing(self.connect()) as connection:
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
        with closing(self.connect()) as connection:
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
        with closing(self.connect()) as connection:
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
        with closing(self.connect()) as connection:
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

    def get_arbitrum_events_page(self, args=None):
        if args is None:
            args = [1000, 0]
        self.log.perf.start("get_arbitrum_events")
        with closing(self.connect()) as connection:
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

    def get_arbitrum_events_since_timestamp(self, params: [int, list[str] | None]) -> list[ProcessedEvent]:
        timestamp = params[0] if len(params) > 0 else None
        events_types = params[1] if len(params) > 1 and len(params[1]) > 0 else None

        if timestamp is None or (not isinstance(timestamp, int) and not isinstance(timestamp, float)):
            raise ValueError("Invalid timestamp, timestamp must be an integer or float")

        if events_types is not None:
            if isinstance(events_types, str):
                events_types = [events_types]
            elif not isinstance(events_types, list):
                raise ValueError("Invalid events_types, events_types must be a list of strings or a string")


        self.log.perf.start("get_arbitrum_events_since_timestamp")
        with closing(self.connect()) as connection:
            with closing(connection.cursor()) as cursor:
                if events_types is None:
                    cursor.execute("SELECT * FROM arbitrum_events WHERE timestamp > ? ORDER BY timestamp DESC", (timestamp,))
                else:
                    placeholder= '?' # For SQLite. See DBAPI paramstyle.
                    placeholders= ', '.join(placeholder for unused in events_types)
                    query= 'SELECT * FROM arbitrum_events WHERE timestamp > ? AND name IN (%s) ORDER BY timestamp DESC' % placeholders
                    cursor.execute(query, (timestamp, *events_types))
                    # cursor.execute("SELECT * FROM arbitrum_events WHERE timestamp > ? AND name IN ({}) ORDER BY timestamp DESC".format(",".join(["?"]*len(events_types))), tuple(events_types)+(timestamp,))
                events = [ProcessedEvent(*event) for event in cursor.fetchall()]
                self.log.debug("Arbitrum events: {}".format(len(events)))
                self.log.perf.end("get_arbitrum_events_since_timestamp")
                return events

    def get_arbitrum_info(self):
        self.log.perf.start("get_arbitrum_info")
        with closing(self.connect()) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute("SELECT * FROM arbitrum_info ORDER BY block DESC LIMIT 1")
                info = ArbitrumInfo(*cursor.fetchone())

                self.log.debug("Arbitrum info: {}".format(info))
                self.log.perf.end("get_arbitrum_info")
                return info

    def get_arbitrum_events_for_stake_contrat_id(self, contract_id: int):
        self.log.perf.start("get_events_for_stake_contrat_id")
        with closing(self.connect()) as connection:
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

    def get_service_node_rewards_contract_id_bls_key_map(self):
        self.log.perf.start("get_service_node_rewards_contract_id_bls_key_map")
        with closing(self.connect()) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute(
                    """
                    SELECT contract_id, pubkey_bls FROM service_node_rewards_contract_id_bls_key_map
                    """
                )
                contract_id_map = {
                    pubkey_bls: contract_id
                    for contract_id, pubkey_bls in cursor.fetchall()
                }
                self.log.debug("Service node rewards contract id bls key map: {}".format(len(contract_id_map)))
                self.log.perf.end("get_service_node_rewards_contract_id_bls_key_map")
                return contract_id_map