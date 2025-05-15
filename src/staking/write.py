import json
import time
from contextlib import closing

from web3 import Web3

from ..db.util import sql_connect_in_write_mode
from ..log import Log
from ..staking.arbitrum import ContributionContractDetails
from ..staking.dataclasses import RewardsInfo, DBNodeExit, VestingContract
from ..oxen.rpc import ServiceNode, NetworkInfo
from ..web3client.abi_manager import ABIData
from ..web3client.event_scanner import ProcessedEvent


class DBWriterStaking:
    def __init__(self, db_path: str, log_level: int, perf: bool = False):
        self.log = Log("db_writer", log_level, enable_perf=perf).logger
        self.db_path = db_path
        self.defer_writing_arbitrum_events = False
        self.deferred_arbitrum_events = []

    def write_nodes_to_staging_db(
            self,
            height: int,
            parsed_nodes: list[ServiceNode],
            # TODO: type the contributor_stake_map properly
            contributions: list[dict[str, int]],
    ):
        self.log.perf.start("write_to_db")

        with closing(sql_connect_in_write_mode(self.db_path)) as connection:
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
        with closing(sql_connect_in_write_mode(self.db_path)) as connection:
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

    def write_exit_list_to_db(self, exit_list: list[DBNodeExit]):
        self.log.perf.start("write_exit_list_to_db")
        with closing(sql_connect_in_write_mode(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:
                self.log.debug("Updating nodes in main with {} exit events".format(len(exit_list)))
                self.log.perf.start("write_exit_list_to_db -> insert exit events")
                cursor.executemany(
                    """
                    UPDATE service_nodes_main SET
                        deregistration_height = ?,
                        exit_type = ?,
                        liquidation_height = ?
                    WHERE pubkey_bls = ?
                    """,
                    (
                        (
                            e.deregistration_height,
                            e.exit_type,
                            e.liquidation_height,
                            e.pubkey_bls,
                        )
                        for e in exit_list
                    )
                )
                inserted_exit_rows = cursor.rowcount

                self.log.perf.end("write_exit_list_to_db -> insert exit events")
                self.log.debug(
                    "Inserted {} rows into exit events".format(inserted_exit_rows)
                )

            connection.commit()
            self.log.perf.end("write_exit_list_to_db")

    def write_network_info_to_db(
            self,
            network: NetworkInfo,
            node_count: int,
            total_staked: int,
            active_node_count: int,
    ):
        self.log.perf.start("write_network_info_to_db")
        with closing(sql_connect_in_write_mode(self.db_path)) as connection:
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
                        total_staked,
                        version
                        )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        total_staked,
                        network.version,
                    ),
                )
                connection.commit()
        self.log.perf.end("write_network_info_to_db")

    def write_rewards_info_to_db(self, rewards_info: list[RewardsInfo]):
        self.log.perf.start("write_rewards_info_to_db")
        with closing(sql_connect_in_write_mode(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:
                self.log.debug("Inserting {} rewards info".format(len(rewards_info)))
                self.log.perf.start("write_rewards_info_to_db -> insert rewards info")

                cursor.executemany(
                    """
                    INSERT INTO rewards_info (
                        address,
                        amount,
                        lifetime_liquidated_stakes,
                        lifetime_locked_stakes,
                        lifetime_rewards,
                        lifetime_unlocked_stakes,
                        locked_stakes,
                        timelocked_stakes
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(address) DO UPDATE SET
                        amount = excluded.amount,
                        lifetime_liquidated_stakes = excluded.lifetime_liquidated_stakes,
                        lifetime_locked_stakes = excluded.lifetime_locked_stakes,
                        lifetime_rewards = excluded.lifetime_rewards,
                        lifetime_unlocked_stakes = excluded.lifetime_unlocked_stakes,
                        locked_stakes = excluded.locked_stakes,
                        timelocked_stakes = excluded.timelocked_stakes;
                    """,
                    (
                        (
                            info.address,
                            info.amount,
                            info.lifetime_liquidated_stakes,
                            info.lifetime_locked_stakes,
                            info.lifetime_rewards,
                            info.lifetime_unlocked_stakes,
                            info.locked_stakes,
                            info.timelocked_stakes
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

    def write_update_rewards_claim_amounts(self, address: str, claimed_stakes: int, claimed_rewards: int):
        self.log.perf.start("write_update_rewards_claim_amounts")
        with closing(sql_connect_in_write_mode(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:
                self.log.debug(f"Updating rewards claim amounts for {address}")
                self.log.perf.start("write_update_rewards_claim_amounts -> update rewards claim amounts")
                cursor.execute(
                    """
                    UPDATE rewards_info SET claimed_stakes = ?, claimed_rewards = ? WHERE address = ?
                    """,
                    (claimed_stakes, claimed_rewards, address),
                )
                updated_rows = cursor.rowcount
                self.log.perf.end("write_update_rewards_claim_amounts -> update rewards claim amounts")
                self.log.debug(
                    "Updated {} rows in rewards_info".format(updated_rows)
                )
            connection.commit()
            self.log.perf.end("write_update_rewards_claim_amounts")

    def write_reset_all_rewards_claim_amounts(self):
        self.log.perf.start("write_reset_all_rewards_claim_amounts")
        with closing(sql_connect_in_write_mode(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:
                self.log.debug("Updating rewards claim amounts for all addresses")
                self.log.perf.start("write_reset_all_rewards_claim_amounts -> update rewards claim amounts")
                cursor.execute(
                    """
                    UPDATE rewards_info SET claimed_stakes = 0, claimed_rewards = 0
                    """
                )
                updated_rows = cursor.rowcount
                self.log.perf.end("write_reset_all_rewards_claim_amounts -> update rewards claim amounts")
                self.log.debug(
                    "Updated {} rows in rewards_info".format(updated_rows)
                )
            connection.commit()
            self.log.perf.end("write_reset_all_rewards_claim_amounts")

    def write_arbitrum_event_to_db(self, event: ProcessedEvent):
        if self.defer_writing_arbitrum_events:
            self.log.debug(f"Deferring arbitrum event write: {event}")
            self.deferred_arbitrum_events.append(event)
            return
        self.log.perf.start("write_arbitrum_event_to_db")
        with closing(sql_connect_in_write_mode(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:
                self.log.debug("Inserting event into arbitrum_events")
                self.log.debug(event)
                self.log.perf.start("write_arbitrum_event_to_db -> insert event")
                cursor.execute(
                    """
                    INSERT INTO arbitrum_events (
                        args,
                        block,
                        log_index,
                        main_arg,
                        name,
                        tx
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        Web3.to_json(dict(event.args)),
                        event.block,
                        event.log_index,
                        event.main_arg,
                        event.name,
                        event.tx,
                    ),
                )
                inserted_event_rows = cursor.rowcount
                self.log.perf.end("write_arbitrum_event_to_db -> insert event")
                self.log.debug(
                    "Inserted {} rows into arbitrum_events".format(inserted_event_rows)
                )
            connection.commit()
            self.log.perf.end("write_arbitrum_event_to_db")

    def write_deferred_arbitrum_events_to_db(self):
        if len(self.deferred_arbitrum_events) == 0:
            self.log.warning("No deferred arbitrum events to write")
            return

        events, self.deferred_arbitrum_events = self.deferred_arbitrum_events, []
        events.sort(key=lambda x: (x.block, x.log_index))

        try:
            self.log.info(f"Writing {len(events)} deferred arbitrum events to db")
            self.write_arbitrum_events_to_db(events)
        except Exception as e:
            self.log.error("Error writing deferred arbitrum events")
            self.log.error(e)
            self.deferred_arbitrum_events = events + self.deferred_arbitrum_events

    def write_arbitrum_events_to_db(self, events: list[ProcessedEvent]):
        self.log.perf.start("write_arbitrum_events_to_db")

        with closing(sql_connect_in_write_mode(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:
                self.log.debug("Inserting {} events into arbitrum_events".format(len(events)))
                self.log.perf.start("write_arbitrum_events_to_db -> insert events")

                cursor.executemany(
                    """
                    INSERT OR REPLACE INTO arbitrum_events (
                        args,
                        block,
                        log_index,
                        main_arg,
                        name,
                        tx
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        (
                            Web3.to_json(dict(event.args)),
                            event.block,
                            event.log_index,
                            event.main_arg,
                            event.name,
                            event.tx,
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

    def write_new_contribution_contract(self, address: str, operator_address: str, service_node_pubkey: str):
        self.log.perf.start("write_new_contribution_contract")
        with closing(sql_connect_in_write_mode(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:
                self.log.debug(f"Inserting new contribution contract")
                cursor.execute("""
                INSERT OR REPLACE INTO contribution_contracts (
                    address,
                    operator_address,
                    service_node_pubkey
                )
                VALUES (?, ?, ?)
                """, (address, operator_address, service_node_pubkey))

                connection.commit()
                self.log.perf.end("write_new_contribution_contract")

    def write_update_contribution_contract_status(self, address: str, status: int):
        self.log.perf.start("write_update_contribution_contract_status")
        with closing(sql_connect_in_write_mode(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:
                self.log.debug(f"Updating contribution contract status to {status}")
                cursor.execute(
                    """
                    UPDATE contribution_contracts SET status = ? WHERE address = ?
                    """,
                    (status, address),
                )

                connection.commit()
                self.log.perf.end("write_update_contribution_contract_status")

    def write_update_contribution_contract_manual_finalize(self, address: str, manual_finalize: bool):
        self.log.perf.start("write_update_contribution_contract_manual_finalize")
        with closing(sql_connect_in_write_mode(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:
                self.log.debug(f"Updating contribution contract manual_finalize to {manual_finalize}")
                cursor.execute(
                    """
                    UPDATE contribution_contracts SET manual_finalize = ? WHERE address = ?
                    """,
                    (manual_finalize, address),
                )

                connection.commit()
                self.log.perf.end("write_update_contribution_contract_manual_finalize")

    def write_update_contribution_contract_fee(self, address: str, fee: int):
        self.log.perf.start("write_update_contribution_contract_fee")
        with closing(sql_connect_in_write_mode(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:
                self.log.debug(f"Updating contribution contract fee to {fee}")
                cursor.execute(
                    """
                    UPDATE contribution_contracts SET fee = ? WHERE address = ?
                    """,
                    (fee, address),
                )

                connection.commit()
                self.log.perf.end("write_update_contribution_contract_fee")

    def write_update_contribution_contract_pubkeys(self, address: str, pubkey_bls: str, service_node_pubkey: str):
        self.log.perf.start("write_update_contribution_contract_pubkeys")
        with closing(sql_connect_in_write_mode(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:
                self.log.debug(f"Updating contribution contract pubkeys")
                cursor.execute(
                    """
                    INSERT INTO contribution_contracts (address, pubkey_bls, service_node_pubkey)
                    VALUES (?, ?, ?)
                    ON CONFLICT(address) DO UPDATE SET
                        pubkey_bls = excluded.pubkey_bls,
                        service_node_pubkey = excluded.service_node_pubkey;
                    """,
                    (address, pubkey_bls, service_node_pubkey),
                )

                connection.commit()
                self.log.perf.end("write_update_contribution_contract_pubkeys")

    def write_update_contribution_contract_contributor(self, contract_address: str, contributor):
        self.log.perf.start("write_update_contribution_contract_contributor")
        with closing(sql_connect_in_write_mode(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:
                self.log.debug(f"Updating contribution contract contributor")
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO contribution_contracts_contributions (
                        address,
                        amount,
                        beneficiary_address,
                        contract_address,
                        reserved
                    )
                    VALUES (?, ?, ?, ?, ?)
                """,
                    (
                        contributor.address,
                        contributor.amount,
                        contributor.beneficiary,
                        contract_address,
                        contributor.reserved
                    ),
                )

                connection.commit()

    def write_delete_contribution_contract_contributor(self, contract_address: str, contributor_address: str):
        self.log.perf.start("write_delete_contribution_contract_contributor")
        with closing(sql_connect_in_write_mode(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:
                self.log.debug(f"Deleting contribution contract contributor")
                cursor.execute(
                    """
                    DELETE FROM contribution_contracts_contributions WHERE address = ? AND contract_address = ?
                    """,
                    (contributor_address, contract_address),
                )

                connection.commit()
                self.log.perf.end("write_delete_contribution_contract_contributor")

    def write_delete_all_contribution_contract_contributors(self, contract_address: str):
        self.log.perf.start("write_delete_all_contribution_contract_contributors")
        with closing(sql_connect_in_write_mode(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:
                self.log.debug(f"Deleting all contribution contract contributors")
                cursor.execute(
                    """
                    DELETE FROM contribution_contracts_contributions WHERE contract_address = ?
                    """,
                    (contract_address,),
                )
                connection.commit()
                self.log.perf.end("write_delete_all_contribution_contract_contributors")

    def write_contribution_contracts_to_db(
            self, contracts: list[ContributionContractDetails], contributions_list: list
    ):
        self.log.perf.start("write_contribution_contracts_to_db")

        with closing(sql_connect_in_write_mode(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:
                self.log.debug("Inserting {} contribution contracts".format(len(contracts)))
                self.log.perf.start("write_contribution_contracts_to_db -> insert contracts")

                cursor.executemany(
                    """
                    INSERT OR REPLACE INTO contribution_contracts (
                        address,
                        fee,
                        manual_finalize,
                        operator_address,
                        pubkey_bls,
                        service_node_pubkey,
                        status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        (
                            contract.address,
                            contract.fee,
                            contract.manual_finalize,
                            contract.operator_address,
                            contract.pubkey_bls,
                            contract.service_node_pubkey,
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
                        contract_address,
                        reserved
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        (
                            contribution["address"],
                            contribution["amount"],
                            contribution["beneficiary_address"],
                            contribution["contract_address"],
                            contribution["reserved"],
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
        with closing(sql_connect_in_write_mode(self.db_path)) as connection:
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
        with closing(sql_connect_in_write_mode(self.db_path)) as connection:
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
        with closing(sql_connect_in_write_mode(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:
                self.log.debug(
                    "Inserting arbitrum info: current block {}, service node rewards balance {}, reward rate pool balance {}".format(
                        current_block, service_node_rewards_balance, reward_rate_pool_balance))
                self.log.perf.start("write_arbitrum_info_to_db -> insert info")

                cursor.execute(
                    "INSERT OR REPLACE INTO arbitrum_info (block, balance_service_node_rewards, balance_reward_rate_pool) VALUES (?, ?, ?)",
                    (current_block, service_node_rewards_balance, reward_rate_pool_balance))

                inserted_info_rows = cursor.rowcount

                self.log.perf.end("write_arbitrum_info_to_db -> insert info")
                self.log.debug(
                    "Inserted {} rows into arbitrum_info".format(inserted_info_rows)
                )

            connection.commit()
            self.log.perf.end("write_arbitrum_info_to_db")

    def write_vesting_contracts(self, vesting_contracts: list[VestingContract]):
        self.log.perf.start("write_vesting_contracts")
        with closing(sql_connect_in_write_mode(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:
                self.log.debug("Inserting {} vesting contracts".format(len(vesting_contracts)))
                self.log.perf.start("write_vesting_contracts -> insert contracts")

                # assert the table is empty
                cursor.execute("SELECT COUNT(*) FROM vesting_contracts")
                assert cursor.fetchone()[0] == 0, "Vesting contract table is not empty"

                cursor.executemany(
                    """
                    INSERT OR REPLACE INTO vesting_contracts (
                        address,
                        beneficiary,
                        initial_amount,
                        initial_beneficiary,
                        revoker,
                        time_end,
                        time_start,
                        transferable_beneficiary
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        (
                            contract.address,
                            contract.beneficiary,
                            contract.initial_amount,
                            contract.initial_beneficiary,
                            contract.revoker,
                            contract.time_end,
                            contract.time_start,
                            contract.transferable_beneficiary,
                        )
                        for contract in vesting_contracts
                    ),
                )

                inserted_contract_rows = cursor.rowcount

                self.log.perf.end("write_vesting_contracts -> insert contracts")
                self.log.debug(
                    "Inserted {} rows into vesting_contracts".format(inserted_contract_rows)
                )

            connection.commit()
            self.log.perf.end("write_vesting_contracts")

    def delete_all_vesting_contracts(self):
        self.log.perf.start("delete_all_vesting_contracts")
        with closing(sql_connect_in_write_mode(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:
                cursor.execute("DELETE FROM vesting_contracts")
                deleted_rows = cursor.rowcount
                self.log.debug(
                    "Cleared {} rows from vesting_contracts".format(deleted_rows)
                )
            connection.commit()
            self.log.perf.end("delete_all_vesting_contracts")

    def write_update_vesting_contract_beneficiary(self, address: str, beneficiary: str):
        self.log.perf.start("write_update_vesting_contract_beneficiary")
        with closing(sql_connect_in_write_mode(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:
                self.log.debug("Updating vesting contract {} beneficiary to {}".format(address, beneficiary))
                self.log.perf.start("write_update_vesting_contract_beneficiary -> update beneficiary")

                cursor.execute(
                    """
                    UPDATE vesting_contracts SET beneficiary = ? WHERE address = ?
                    """,
                    (beneficiary, address),
                )

                updated_rows = cursor.rowcount

                self.log.perf.end("write_update_vesting_contract_beneficiary -> update beneficiary")
                self.log.debug(
                    "Updated {} rows in vesting_contracts".format(updated_rows)
                )

            connection.commit()
            self.log.perf.end("write_update_vesting_contract_beneficiary")

    def delete_all_events(self):
        self.log.perf.start("delete_all_events")
        with closing(sql_connect_in_write_mode(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:
                self.log.debug("Deleting all events from the db")

                cursor.execute("""Delete from arbitrum_events""")

                deleted_rows = cursor.rowcount

                self.log.debug(
                    "Cleared {} rows from vesting_contracts".format(deleted_rows)
                )

            connection.commit()
            self.log.perf.end("delete_all_events")

    def delete_all_contrib_contracts_and_contributors(self):
        self.log.perf.start("delete_all_contrib_contracts_and_contributors")
        with closing(sql_connect_in_write_mode(self.db_path)) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:
                cursor.execute("""Delete from contribution_contracts_contributions""")
                deleted_contributions_rows = cursor.rowcount

                self.log.debug(
                    "Cleared {} rows from contribution_contracts_contributions".format(deleted_contributions_rows)
                )

                cursor.execute("""Delete from contribution_contracts""")
                deleted_contract_rows = cursor.rowcount

                self.log.debug(
                    "Cleared {} rows from contribution_contracts".format(deleted_contract_rows)
                )

            connection.commit()
            self.log.perf.end("delete_all_contrib_contracts_and_contributors")
