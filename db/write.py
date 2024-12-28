import json
import sqlite3
import time
from contextlib import closing

from web3 import Web3

from arbitrum import ContributionContractDetails
from db.dataclasses import RewardsInfo
from log import Log
from oxen.rpc import ServiceNode, NetworkInfo
from web3client.abi_manager import ABIData
from web3client.event_scanner import ProcessedEvent


class DBWriter:
    def __init__(self, db_path: str, log_level: int, perf: bool = False):
        self.db_path = db_path
        self.log = Log("db_writer", log_level, enable_perf=perf).logger

    def write_nodes_to_staging_db(
        self,
        height: int,
        parsed_nodes: list[ServiceNode],
        # TODO: type the contributor_stake_map properly
        contributions: list[dict[str, int]],
    ):
        self.log.perf.start("write_to_db")

        with closing(sqlite3.connect(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:

                self.log.debug("Inserting {} service nodes".format(len(parsed_nodes)))
                self.log.perf.start("write_nodes_to_staging_db -> insert nodes")

                cursor.executemany(
                    """
                    INSERT INTO service_nodes_staging (
                        active,
                        contract_id,
                        decommission_count,
                        earned_downtime_blocks,
                        fetched_block_height,
                        funded,
                        is_liquidatable,
                        is_removable,
                        last_reward_block_height,
                        last_uptime_proof,
                        lokinet_version,
                        operator_address,
                        operator_fee,
                        payable,
                        pubkey_bls,
                        pubkey_ed25519,
                        public_ip,
                        pulse_votes,
                        quorumnet_port,
                        registration_height,
                        registration_hf_version,
                        requested_unlock_height,
                        service_node_pubkey,
                        service_node_version,
                        staking_requirement,
                        state_height,
                        storage_lmq_port,
                        storage_port,
                        storage_server_version,
                        swarm,
                        swarm_id,
                        total_contributed
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        (
                            node.get("active"),
                            node.get("contract_id"),
                            node.get("decommission_count"),
                            node.get("earned_downtime_blocks"),
                            height,
                            node.get("funded"),
                            node.get("is_liquidatable"),
                            node.get("is_removable"),
                            node.get("last_reward_block_height"),
                            node.get("last_uptime_proof"),
                            node.get("lokinet_version"),
                            node.get("operator_address"),
                            node.get("operator_fee"),
                            node.get("payable"),
                            node.get("pubkey_bls"),
                            node.get("pubkey_ed25519"),
                            node.get("public_ip"),
                            node.get("pulse_votes"),
                            node.get("quorumnet_port"),
                            node.get("registration_height"),
                            node.get("registration_hf_version"),
                            node.get("requested_unlock_height"),
                            node.get("service_node_pubkey"),
                            node.get("service_node_version"),
                            node.get("staking_requirement"),
                            node.get("state_height"),
                            node.get("storage_lmq_port"),
                            node.get("storage_port"),
                            node.get("storage_server_version"),
                            node.get("swarm"),
                            node.get("swarm_id"),
                            node.get("total_contributed"),
                        )
                        for node in parsed_nodes
                    ),
                )

                inserted_nodes_rows = cursor.rowcount

                self.log.perf.end("write_nodes_to_staging_db -> insert nodes")
                self.log.debug(
                    "Inserted {} rows into service_nodes_staging".format(inserted_nodes_rows)
                )
                self.log.debug("Inserting {} service node contributions".format(len(contributions)))
                self.log.perf.start("write_nodes_to_staging_db -> insert contributions")

                cursor.executemany(
                    """
                    INSERT OR REPLACE INTO service_nodes_contributions_staging (
                        address, 
                        amount,
                        beneficiary, 
                        contract_id,
                        fetched_block_height
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        (
                            contribution["address"],
                            contribution["amount"],
                            contribution["beneficiary"],
                            contribution["contract_id"],
                            height,
                        )
                        for contribution in contributions
                    ),
                )

                inserted_contributions_rows = cursor.rowcount

                self.log.perf.end("write_nodes_to_staging_db -> insert contributions")
                self.log.debug(
                    "Inserted {} rows into service_nodes_contributions_staging".format(
                        inserted_contributions_rows
                    )
                )

            connection.commit()
            self.log.perf.end("write_to_db")

    def write_nodes_to_main_db(self, immutable_height: int):
        """
        Gets all nodes from the staging db at or below the immutable_height and writes them to the main db then remove
        those nodes from the staging db.
        """
        self.log.perf.start("write_nodes_to_main_db")
        with closing(sqlite3.connect(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:
                self.log.perf.start("write_nodes_to_main_db -> select nodes")

                cursor.execute(
                    """
                    SELECT * FROM service_nodes_staging WHERE fetched_block_height = ?
                    """,
                    (immutable_height,),
                )
                nodes = cursor.fetchall()
                selected_nodes_count = len(nodes)

                self.log.perf.end("write_nodes_to_main_db -> select nodes")
                self.log.info("Found {} nodes to write to main db".format(selected_nodes_count))

                # We only want to continue here if there are any nodes ready to commit.
                if selected_nodes_count == 0:
                    self.log.debug("No nodes ready to commit")
                    return

                self.log.perf.start("write_nodes_to_main_db -> insert nodes")

                cursor.executemany(
                    """
                    INSERT OR REPLACE INTO service_nodes_main (
                        active,
                        contract_id,
                        decommission_count,
                        earned_downtime_blocks,
                        fetched_block_height,
                        funded,
                        is_liquidatable,
                        is_removable,
                        last_reward_block_height,
                        last_uptime_proof,
                        lokinet_version,
                        operator_address,
                        operator_fee,
                        payable,
                        pubkey_bls,
                        pubkey_ed25519,
                        public_ip,
                        pulse_votes,
                        quorumnet_port,
                        registration_height,
                        registration_hf_version,
                        requested_unlock_height,
                        service_node_pubkey,
                        service_node_version,
                        staking_requirement,
                        state_height,
                        storage_lmq_port,
                        storage_port,
                        storage_server_version,
                        swarm,
                        swarm_id,
                        total_contributed
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    nodes,
                )

                inserted_or_updated_rows = cursor.rowcount

                self.log.perf.end("write_nodes_to_main_db -> insert nodes")
                self.log.info("Wrote {} rows to main db".format(inserted_or_updated_rows))

                if inserted_or_updated_rows != len(nodes):
                    self.log.error(
                        "Inserted or updated {} rows, but expected {}".format(
                            inserted_or_updated_rows, len(nodes)
                        )
                    )
                    connection.rollback()
                    self.log.perf.end("write_nodes_to_main_db")
                    return

                self.log.perf.start("write_nodes_to_main_db -> select contributions")

                cursor.execute(
                    """
                    SELECT * FROM service_nodes_contributions_staging WHERE fetched_block_height = ?
                    """,
                    (immutable_height,),
                )
                contributions = cursor.fetchall()
                selected_contributions_count = len(contributions)

                self.log.perf.end("write_nodes_to_main_db -> select contributions")
                self.log.debug(
                    "Found {} contributions to write to main db".format(
                        selected_contributions_count
                    )
                )
                self.log.perf.start("write_nodes_to_main_db -> insert contributions")

                cursor.executemany(
                    """
                    INSERT OR REPLACE INTO service_nodes_contributions_main (address, amount, beneficiary, contract_id, fetched_block_height)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    contributions,
                )

                inserted_contributions_rows = cursor.rowcount

                self.log.perf.end("write_nodes_to_main_db -> insert contributions")
                self.log.info("Wrote {} rows to main db".format(inserted_contributions_rows))

                if inserted_contributions_rows != len(contributions):
                    self.log.error(
                        "Inserted {} rows, but expected {}".format(
                            inserted_contributions_rows, len(contributions)
                        )
                    )
                    connection.rollback()
                    return

                self.log.perf.start("write_nodes_to_main_db -> delete nodes")

                cursor.execute(
                    """
                    DELETE FROM service_nodes_staging WHERE fetched_block_height <= ?
                    """,
                    (immutable_height,),
                )

                deleted_rows = cursor.rowcount

                self.log.perf.end("write_nodes_to_main_db -> delete nodes")
                self.log.info("Deleted {} rows from staging db".format(deleted_rows))
                self.log.perf.start("write_nodes_to_main_db -> delete contributions")

                cursor.execute(
                    """
                    DELETE FROM service_nodes_contributions_staging WHERE fetched_block_height <= ?
                    """,
                    (immutable_height,),
                )

                deleted_contributions_rows = cursor.rowcount

                self.log.perf.end("write_nodes_to_main_db -> delete contributions")
                self.log.info(
                    "Deleted {} rows from staging contributions db".format(
                        deleted_contributions_rows
                    )
                )

                connection.commit()
                self.log.info("Transaction committed successfully")

        self.log.perf.end("write_nodes_to_main_db")

    def write_network_info_to_db(
        self,
        network: NetworkInfo,
        node_count: int,
        active_node_count: int,
    ):
        self.log.perf.start("write_network_info_to_db")
        with closing(sqlite3.connect(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO network_info (
                        id,
                        active_node_count,
                        block_hash,
                        block_height,
                        block_timestamp,
                        hard_fork,
                        immutable_block_hash,
                        immutable_block_height,
                        max_stakers,
                        min_operator_contribution,
                        node_count,
                        nettype,
                        pulse_target_timestamp,
                        staking_requirement,
                        version
                        )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        1,
                        active_node_count,
                        network.block_hash,
                        network.block_height,
                        time.time().__floor__(),
                        network.hard_fork,
                        network.immutable_block_hash,
                        network.immutable_block_height,
                        network.max_stakers,
                        network.min_operator_contribution,
                        node_count,
                        network.nettype,
                        network.pulse_target_timestamp,
                        network.staking_requirement,
                        network.version,
                    ),
                )
                connection.commit()
        self.log.perf.end("write_network_info_to_db")

    def write_rewards_info_to_db(self, rewards_info: list[RewardsInfo]):
        self.log.perf.start("write_rewards_info_to_db")
        with closing(sqlite3.connect(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:
                self.log.debug("Inserting {} rewards info".format(len(rewards_info)))
                self.log.perf.start("write_rewards_info_to_db -> insert rewards info")

                cursor.executemany(
                    """
                    INSERT OR REPLACE INTO rewards_info (address, rewards)
                    VALUES (?, ?)
                    """,
                    (
                        (
                            info.address,
                            info.rewards,
                        )
                        for info in rewards_info
                    ),
                )

                inserted_rewards_rows = cursor.rowcount

                self.log.perf.end("write_rewards_info_to_db -> insert rewards info")
                self.log.debug(
                    "Inserted {} rows into rewards_info".format(inserted_rewards_rows)
                )

            connection.commit()
            self.log.perf.end("write_rewards_info_to_db")

    def write_arbitrum_events_to_db(self, events: list[ProcessedEvent]):
        self.log.perf.start("write_arbitrum_events_to_db")

        with closing(sqlite3.connect(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:

                self.log.debug("Inserting {} events into arbitrum_events".format(len(events)))
                self.log.perf.start("write_arbitrum_events_to_db -> insert events")

                cursor.executemany(
                    """
                    INSERT OR REPLACE INTO arbitrum_events (
                        block,
                        timestamp,
                        tx,
                        name,
                        main_arg,
                        args
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        (
                            event.block,
                            event.timestamp,
                            "0x" + event.tx,
                            event.name,
                            event.main_arg,
                            Web3.to_json(dict(event.args)),
                        )
                        for event in events
                    ),
                )

                inserted_or_updated_rows_count = cursor.rowcount

                self.log.perf.end("write_arbitrum_events_to_db -> insert events")
                self.log.debug(
                    "Inserted or updated {} rows into arbitrum_events".format(
                        inserted_or_updated_rows_count
                    )
                )

            connection.commit()
            self.log.perf.end("write_arbitrum_events_to_db")

    def write_contribution_contracts_to_db(
        self, contracts: list[ContributionContractDetails], contributions_list: list
    ):
        self.log.perf.start("write_contribution_contracts_to_db")

        with closing(sqlite3.connect(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:

                self.log.debug("Inserting {} contribution contracts".format(len(contracts)))
                self.log.perf.start("write_contribution_contracts_to_db -> insert contracts")

                cursor.executemany(
                    """
                    INSERT OR REPLACE INTO contribution_contracts (
                        address,
                        fee,
                        operator_address,
                        pubkey_bls,
                        service_node_pubkey,
                        service_node_signature,
                        status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        (
                            contract.address,
                            contract.fee,
                            contract.operator_address,
                            contract.pubkey_bls,
                            contract.service_node_pubkey,
                            contract.service_node_signature,
                            contract.status,
                        )
                        for contract in contracts
                    ),
                )

                inserted_contract_rows = cursor.rowcount

                self.log.perf.end("write_contribution_contracts_to_db -> insert contracts")
                self.log.debug(
                    "Inserted or Updated {} rows into contribution_contracts".format(
                        inserted_contract_rows
                    )
                )
                self.log.perf.start("write_contribution_contracts_to_db -> delete contributions")

                # The contributors for a contact need to be deleted before the contract can be inserted again to account
                #   for contract resets, or contributors leaving the contract. We could read from the db and only delete
                #   the missing ones but this should be more performant.
                # TODO: investigate a better solution
                cursor.executemany(
                    """DELETE FROM contribution_contracts_contributions WHERE contract_address = ?""",
                    ((
                        contract.address,
                    )
                        for contract in contracts)
                )

                deleted_contributions_rows = cursor.rowcount

                self.log.perf.end("write_contribution_contracts_to_db -> delete contributions")
                self.log.debug(
                    "Deleted {} rows from contribution_contracts_contributions".format(
                        deleted_contributions_rows
                    )
                )
                self.log.debug(
                    "Inserting {} contract contributions".format(len(contributions_list))
                )
                self.log.perf.start(
                    "write_contribution_contracts_to_db -> insert contribution contracts contributions"
                )

                cursor.executemany(
                    """
                    INSERT INTO contribution_contracts_contributions (
                        address,
                        amount,
                        beneficiary_address,
                        contract_address
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        (
                            contribution["address"],
                            contribution["amount"],
                            contribution["beneficiary_address"],
                            contribution["contract_address"],
                        )
                        for contribution in contributions_list
                    ),
                )

                inserted_contributions_rows = cursor.rowcount

                self.log.perf.end(
                    "write_contribution_contracts_to_db -> insert contribution contracts contributions"
                )
                self.log.debug(
                    "Inserted {} rows into contribution_contracts_contributions".format(
                        inserted_contributions_rows
                    )
                )

            connection.commit()
            self.log.perf.end("write_contribution_contracts_to_db")

    def write_smart_contract_abis_to_db(self, abis: list[ABIData]):
        self.log.perf.start("write_smart_contract_abis_to_db")
        with closing(sqlite3.connect(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:

                self.log.debug("Inserting {} smart contract abis".format(len(abis)))
                self.log.perf.start("write_smart_contract_abis_to_db -> insert abis")

                cursor.executemany(
                    """
                    INSERT OR REPLACE INTO smart_contract_abis (
                        name,
                        abi,
                        bytecode,
                        deployed_bytecode
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        (
                            abi.name,
                            json.dumps(abi.abi),
                            abi.bytecode,
                            abi.deployed_bytecode,
                        )
                        for abi in abis
                    ),
                )

                inserted_abi_rows = cursor.rowcount

                self.log.perf.end("write_smart_contract_abis_to_db -> insert abis")
                self.log.debug(
                    "Inserted {} rows into smart_contract_abis".format(inserted_abi_rows)
                )

            connection.commit()
            self.log.perf.end("write_smart_contract_abis_to_db")

    def write_smart_contract_details_to_db(
        self,
        contracts,
    ):
        self.log.perf.start("write_smart_contract_details_to_db")
        with closing(sqlite3.connect(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:

                self.log.debug("Inserting {} smart contract details".format(len(contracts)))
                self.log.perf.start("write_smart_contract_details_to_db -> insert contracts")

                cursor.executemany(
                    """
                    INSERT OR REPLACE INTO smart_contracts (
                        address,
                        name
                    )
                    VALUES (?, ?)
                    """,
                    (
                        (
                            contract.get("address"),
                            contract.get("name"),
                        )
                        for contract in contracts
                    ),
                )

                inserted_details_rows = cursor.rowcount

                self.log.perf.end("write_smart_contract_details_to_db -> insert details")
                self.log.debug(
                    "Inserted {} rows into smart_contract_details".format(inserted_details_rows)
                )

            connection.commit()
            self.log.perf.end("write_smart_contract_details_to_db")

    def write_arbitrum_info_to_db(self, current_block, service_node_rewards_balance, reward_rate_pool_balance):
        self.log.perf.start("write_arbitrum_info_to_db")
        with closing(sqlite3.connect(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:
                self.log.debug(
                    "Inserting arbitrum info: current block {}, service node rewards balance {}, reward rate pool balance {}".format(
                        current_block, service_node_rewards_balance, reward_rate_pool_balance))
                self.log.perf.start("write_arbitrum_info_to_db -> insert info")
                
                cursor.execute("INSERT OR REPLACE INTO arbitrum_info (block, balance_service_node_rewards, balance_reward_rate_pool) VALUES (?, ?, ?)", (current_block, service_node_rewards_balance, reward_rate_pool_balance))

                inserted_info_rows = cursor.rowcount

                self.log.perf.end("write_arbitrum_info_to_db -> insert info")
                self.log.debug(
                    "Inserted {} rows into arbitrum_info".format(inserted_info_rows)
                )

            connection.commit()
            self.log.perf.end("write_arbitrum_info_to_db")
