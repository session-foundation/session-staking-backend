import asyncio
import logging
import time
from datetime import datetime
from attr import dataclass

from eth_typing import ChecksumAddress
from eth_utils import is_checksum_address, to_checksum_address
from web3 import AsyncWeb3, WebSocketProvider

from src.config_validate import validate_log_config, validate_contract_addresses
from src.db.util import is_db_initialized, init_db
from src.log import Log
from src.staking.dataclasses import VestingContract
from src.staking.read import DBReaderStaking
from src.staking.write import DBWriterStaking
from src.web3client.contracts_ws.ierc_1967 import IERC1967
from src.web3client.contracts_ws.ownable_2_step_upgradeable import Ownable2StepUpgradeable
from src.web3client.contracts_ws.pausable_upgradeable import PausableUpgradeable
from src.web3client.contracts_ws.reward_rate_pool import RewardRatePool
from src.web3client.contracts_ws.service_node_contribution_factory import ServiceNodeContributionFactory
from src.web3client.contracts_ws.service_node_rewards import ServiceNodeRewards
from src.web3client.contracts_ws.token import Token
from src.web3client.contracts_ws.token_vesting_staking import TokenVestingStaking
from src.web3client.contrib_contract_details import load_contributor_contract_details
from src.web3client.event_queue_manager import EventQueueManager

log = Log("event_ws", enable_perf=True).logger
global_db_writer: DBWriterStaking | None = None
global_db_reader: DBReaderStaking | None = None
event_queue: EventQueueManager | None = None
sn_contrib_factory: ServiceNodeContributionFactory | None = None


@dataclass(init=False)
class VestingContractDetails:
    beneficiary: ChecksumAddress
    vesting_address: ChecksumAddress
    amount: int
    start: int
    end: int
    transferable_beneficiary: bool
    revoker: ChecksumAddress
    SESH: ChecksumAddress
    rewards_contract: ChecksumAddress
    sn_contrib_factory: ChecksumAddress

    def __init__(self, beneficiary, vesting_address, amount, start, end, transferable_beneficiary, revoker, SESH,
                 rewards_contract, sn_contrib_factory):
        self.beneficiary = beneficiary
        self.vesting_address = vesting_address
        self.amount = Token.to_atomic(float(amount))
        self.start = int(datetime.fromisoformat(start).timestamp())
        self.end = int(datetime.fromisoformat(end).timestamp())
        self.transferable_beneficiary = str.lower(transferable_beneficiary) == "true"
        self.revoker = revoker
        self.SESH = SESH
        self.rewards_contract = rewards_contract
        self.sn_contrib_factory = sn_contrib_factory

        assert is_checksum_address(self.beneficiary)
        assert is_checksum_address(self.vesting_address)
        assert self.amount > 0
        assert self.start < self.end
        assert self.transferable_beneficiary is not None
        assert is_checksum_address(self.revoker)
        assert is_checksum_address(self.SESH)
        assert is_checksum_address(self.rewards_contract)
        assert is_checksum_address(self.sn_contrib_factory)


@dataclass
class EventScannerConfig:
    log_level: int
    log_level_generic: str | None
    enable_perf: bool | None
    ws_max_run_depth: int
    ws_providers: list[str]
    ws_max_size: int
    genesis_block: int
    addr_token: ChecksumAddress
    addr_sn_contrib_factory: ChecksumAddress
    addr_sn_rewards: ChecksumAddress
    addr_reward_rate_pool: ChecksumAddress
    sqlite_db: str
    sqlite_schema: str
    db_reset_events_on_startup: bool
    db_reset_contrib_on_startup: bool
    reset_vesting_contracts_on_startup: bool
    vesting_contract_details: list[VestingContractDetails]
    ws_watch_token_events: bool
    run_once_as_script: bool = False

    def __post_init__(self):
        self.addr_token = to_checksum_address(self.addr_token)
        self.addr_sn_contrib_factory = to_checksum_address(self.addr_sn_contrib_factory)
        self.addr_sn_rewards = to_checksum_address(self.addr_sn_rewards)
        self.addr_reward_rate_pool = to_checksum_address(self.addr_reward_rate_pool)


async def load_vesting_staking_contracts(w3: AsyncWeb3, details: list[VestingContractDetails]):
    contract_interface = TokenVestingStaking(w3=w3, db_writer=global_db_writer, log=log, event_queue=event_queue)
    token_contract = Token(w3=w3, db_writer=global_db_writer, log=log).factory(details[0].SESH)

    if global_db_reader.has_vesting_contracts():
        if len(details) > 0:
            log.warning("Vesting contracts already loaded in database, skipping provided contracts.")
        address_list = [contract.address for contract in global_db_reader.get_vesting_contracts()]
    else:
        if len(details) == 0:
            log.warning(
                "No vesting contracts found in database and none were provided to load. Skipping vesting contract loading.")
            return

        address_list = [contract.vesting_address for contract in details]

        now = time.time()
        res = await contract_interface.batch_get_details(address_list, token_contract)

        contracts = []
        for i in range(0, len(res), contract_interface.batch_items):
            known_details = details[i // contract_interface.batch_items]
            beneficiary = res[i]
            revoker = res[i + 1]
            amount = res[i + 2]
            transferable_beneficiary = res[i + 3]
            start = res[i + 4]
            end = res[i + 5]
            SESH = res[i + 6]
            rewards_contract = res[i + 7]
            sn_contrib_factory = res[i + 8]

            assert revoker == known_details.revoker, f"Expected {known_details.revoker}, got {revoker}"

            if start < now:
                assert amount == known_details.amount, f"Expected {known_details.amount}, got {amount}"
            # TODO: consider checking staked amounts and asserting those

            assert transferable_beneficiary == known_details.transferable_beneficiary, f"Expected {known_details.transferable_beneficiary}, got {transferable_beneficiary}"
            if not transferable_beneficiary:
                assert beneficiary == known_details.beneficiary, f"Expected {known_details.beneficiary}, got {beneficiary}"
            # TODO: consider checking if beneficiary has changed and is correct

            assert start == known_details.start, f"Expected {known_details.start}, got {start}"
            assert end == known_details.end, f"Expected {known_details.end}, got {end}"
            assert SESH == known_details.SESH, f"Expected {known_details.SESH}, got {SESH}"
            assert rewards_contract == known_details.rewards_contract, f"Expected {known_details.rewards_contract}, got {rewards_contract}"
            assert sn_contrib_factory == known_details.sn_contrib_factory, f"Expected {known_details.sn_contrib_factory}, got {sn_contrib_factory}"

            contracts.append(VestingContract(
                address=known_details.vesting_address,
                beneficiary=beneficiary,
                initial_amount=known_details.amount,
                initial_beneficiary=known_details.beneficiary,
                revoker=revoker,
                time_end=end,
                time_start=start,
                transferable_beneficiary=transferable_beneficiary,
            ))

        global_db_writer.write_vesting_contracts(contracts)

        # Verify that the contracts are the same coming out of the db
        db_vesting_contracts = global_db_reader.get_vesting_contracts()
        for i in range(len(contracts)):
            contract = contracts[i]
            db_contract = db_vesting_contracts[i]
            if not contract.transferable_beneficiary:
                assert contract.beneficiary == db_contract.beneficiary, f"Expected {contract.beneficiary}, got {db_contract.beneficiary}"

            assert contract.revoker == db_contract.revoker, f"Expected {contract.revoker}, got {db_contract.revoker}"
            if contract.time_start < now:
                assert contract.initial_amount == db_contract.initial_amount, f"Expected {contract.initial_amount}, got {db_contract.initial_amount}"

            assert contract.time_start == db_contract.time_start, f"Expected {contract.time_start}, got {db_contract.time_start}"
            assert contract.time_end == db_contract.time_end, f"Expected {contract.time_end}, got {db_contract.time_end}"
            assert contract.transferable_beneficiary == db_contract.transferable_beneficiary, f"Expected {contract.transferable_beneficiary}, got {db_contract.transferable_beneficiary}"

            log.info(
                f"Added vesting contract {contract.address} with initial balance {contract.initial_amount} for {contract.beneficiary}")

    log.info(f"Subscribing to {len(address_list)} vesting contracts")
    contract_interface.create_subscriptions(address=address_list)


async def init_global_contracts(w3: AsyncWeb3, config: EventScannerConfig):
    global event_queue, sn_contrib_factory

    last_event_block = global_db_reader.get_last_fetched_arbitrum_event_block_height()
    start_block = last_event_block + 1 if last_event_block else config.genesis_block
    log.info(f"Last block for an event from the database: {last_event_block}, starting from block {start_block}")

    event_queue = EventQueueManager(w3=w3, log=log, start_block=start_block, max_run_depth=config.ws_max_run_depth)

    await load_vesting_staking_contracts(w3, details=config.vesting_contract_details)

    sn_contrib_factory = ServiceNodeContributionFactory(w3=w3, db_writer=global_db_writer, db_reader=global_db_reader,
                                                        log=log, event_queue=event_queue)
    sn_contrib_factory.create_subscriptions(address=config.addr_sn_contrib_factory)

    ServiceNodeRewards(w3=w3, db_writer=global_db_writer, log=log, event_queue=event_queue).create_subscriptions(
        config.addr_sn_rewards,
    )

    RewardRatePool(w3=w3, db_writer=global_db_writer, log=log, event_queue=event_queue).create_subscriptions(
        config.addr_reward_rate_pool
    )

    Ownable2StepUpgradeable(w3=w3, db_writer=global_db_writer, log=log, event_queue=event_queue).create_subscriptions(
        [config.addr_sn_contrib_factory, config.addr_sn_rewards, config.addr_reward_rate_pool]
    )

    PausableUpgradeable(w3=w3, db_writer=global_db_writer, log=log, event_queue=event_queue).create_subscriptions(
        [config.addr_sn_contrib_factory, config.addr_sn_rewards]
    )

    IERC1967(w3=w3, db_writer=global_db_writer, log=log, event_queue=event_queue).create_subscriptions(
        [config.addr_sn_contrib_factory, config.addr_sn_rewards, config.addr_reward_rate_pool]
    )

    if config.ws_watch_token_events:
        log.warning("Watching all token events, this may greatly increase the rescan time (ws_watch_token_events=True)")
        Token(w3=w3, db_writer=global_db_writer, log=log, event_queue=event_queue).create_subscriptions(
            config.addr_token
        )


async def monitor_events(w3: AsyncWeb3, run_once_as_script=False):
    existing_sn_contract_addresses = global_db_reader.get_arbitrum_event_main_args_by_name(
        "NewServiceNodeContributionContract")
    for address in existing_sn_contract_addresses:
        assert is_checksum_address(
            address), f"Invalid existing NewServiceNodeContributionContract contract address: {address}"

    global_db_writer.defer_writing_arbitrum_events = True
    sn_contrib_factory.add_existing_contribution_contracts(existing_sn_contract_addresses)
    await event_queue.run()
    sn_contrib_factory.bootstrap_contribution_contracts()
    await event_queue.run()

    # WIP: To support old contracts we will need this but it isnt working yet TODO: DELETE THIS AFTER EVENTS ARE AVAILABLE
    # await load_contributor_contract_details(w3, existing_sn_contract_addresses)

    global_db_writer.defer_writing_arbitrum_events = False
    global_db_writer.write_deferred_arbitrum_events_to_db()

    assert len(event_queue.sub_queue) == 0 and len(
        event_queue.event_queue) == 0 and len(
        global_db_writer.deferred_arbitrum_events) == 0, \
        f"Expected all queues to be empty." \
        f"Deferred DB write events: {len(global_db_writer.deferred_arbitrum_events)}"

    log.info(f"Created {len(w3.subscription_manager.subscriptions)} subscriptions")
    log.perf.end("startup_till_processing_websocket_subscriptions")
    if run_once_as_script:
        log.info("run_once_as_script is True, exiting...")
        return
    else:
        await w3.subscription_manager.handle_subscriptions()


async def start(config: EventScannerConfig):
    log.perf.start("startup_till_processing_websocket_subscriptions")
    global global_db_writer, global_db_reader, event_queue
    # This loop repeats if the connection is lost, to reestablish the connection: when that happens
    # we need to re-subscribe and re-fetch any lost events that might have happened during the
    # disconnect (or restart).
    log.setLevel(config.log_level)

    validate_log_config(config)
    validate_contract_addresses(config)

    if config.log_level_generic is not None:
        logging.getLogger(None).setLevel(config.log_level_generic)

    if not is_db_initialized(config.sqlite_db):
        log.info(f"Initializing database {config.sqlite_db} with schema {config.sqlite_schema}")
        init_db(config.sqlite_db, config.sqlite_schema)

    global_db_writer = DBWriterStaking(db_path=config.sqlite_db, log_level=config.log_level, perf=config.enable_perf)
    global_db_reader = DBReaderStaking(db_path=config.sqlite_db, log_level=config.log_level, perf=config.enable_perf)

    if config.db_reset_events_on_startup:
        log.warning("Deleting events database on startup (db_reset_events_on_startup=True)")
        global_db_writer.delete_all_events()

    if config.db_reset_contrib_on_startup:
        log.warning("Deleting contrib contracts database on startup (db_reset_contrib_on_startup=True)")
        global_db_writer.delete_all_contrib_contracts_and_contributors()

    if config.reset_vesting_contracts_on_startup:
        log.warning("Deleting vesting contracts database on startup (reset_vesting_contracts_on_startup=True)")
        global_db_writer.delete_all_vesting_contracts()

    log.info("Starting event scanner")
    provider = config.ws_providers[0]
    async for w3 in AsyncWeb3(
            WebSocketProvider(provider, websocket_kwargs={"max_size": config.ws_max_size}, request_timeout=300)
    ):
        # TODO: investigate if this properly handles disconnects
        await init_global_contracts(w3, config)
        await asyncio.create_task(monitor_events(w3=w3, run_once_as_script=config.run_once_as_script))
        if config.run_once_as_script:
            log.info("Exiting websocket disconnection loop as run_once_as_script is True")
            break


def init_ws_event_scanner(config: EventScannerConfig):
    asyncio.run(start(config))
