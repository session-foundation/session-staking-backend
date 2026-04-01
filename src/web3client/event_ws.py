import asyncio
import logging
import time
from datetime import datetime
from functools import partial

from attr import dataclass

from eth_typing import ChecksumAddress
from eth_utils import is_checksum_address, to_checksum_address
from web3 import AsyncWeb3, WebSocketProvider
from web3._utils.events import get_event_data
from web3.auto.gethdev import async_w3
from web3.utils.subscriptions import NewHeadsSubscriptionContext, NewHeadsSubscription

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
from src.web3client.event_queue_manager import EventQueueManager

log = Log("event_ws", enable_perf=True).logger
global_db_writer: DBWriterStaking | None = None
global_db_reader: DBReaderStaking | None = None
event_queue: EventQueueManager | None = None
sn_contrib_factory: ServiceNodeContributionFactory | None = None

topic_map = {}
event_addresses = set()

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

        # TODO: decide if we want this
        # assert is_checksum_address(self.beneficiary)
        # assert is_checksum_address(self.vesting_address)
        # assert self.amount > 0
        # assert self.start < self.end
        # assert self.transferable_beneficiary is not None
        # assert is_checksum_address(self.revoker)
        # assert is_checksum_address(self.SESH)
        # assert is_checksum_address(self.rewards_contract)
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
    contrib_factory_start_block: int
    addr_token: ChecksumAddress
    addr_sn_contrib_factory: ChecksumAddress
    addr_sn_rewards: ChecksumAddress
    addr_reward_rate_pool: ChecksumAddress
    get_logs_cap: int
    refresh_block_interval: int
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
    #token_contract = Token(w3=w3, db_writer=global_db_writer, log=log).factory(details[0].SESH)

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
        #res = await contract_interface.batch_get_details(address_list, token_contract
        res = []
        contracts = []
        for known_details in details:
            #known_details = details[i // contract_interface.batch_items]
            #beneficiary = res[i]
            #revoker = res[i + 1]
            # amount = res[i + 2]
            #transferable_beneficiary = res[i + 3]
            #start = res[i + 4]
            #end = res[i + 5]
            #SESH = res[i + 6]
            #rewards_contract = res[i + 7]
            #sn_contrib_factory = res[i + 8]

            # assert revoker == known_details.revoker, f"Expected {known_details.revoker}, got {revoker}"

            # if start < now:
            #     assert amount == known_details.amount, f"Expected {known_details.amount}, got {amount}"
            # TODO: consider checking staked amounts and asserting those

            # assert transferable_beneficiary == known_details.transferable_beneficiary, f"Expected {known_details.transferable_beneficiary}, got {transferable_beneficiary}"
            # if not transferable_beneficiary:
            #     assert beneficiary == known_details.beneficiary, f"Expected {known_details.beneficiary}, got {beneficiary}"
            # TODO: consider checking if beneficiary has changed and is correct

            # assert start == known_details.start, f"Expected {known_details.start}, got {start}"
            # assert end == known_details.end, f"Expected {known_details.end}, got {end}"
            # assert SESH == known_details.SESH, f"Expected {known_details.SESH}, got {SESH}"
            # assert rewards_contract == known_details.rewards_contract, f"Expected {known_details.rewards_contract}, got {rewards_contract}"
            # assert sn_contrib_factory == known_details.sn_contrib_factory, f"Expected {known_details.sn_contrib_factory}, got {sn_contrib_factory}"

            contracts.append(VestingContract(
                address=known_details.vesting_address,
                beneficiary=known_details.beneficiary,
                initial_amount=known_details.amount,
                initial_beneficiary=known_details.beneficiary,
                revoker=known_details.revoker,
                time_end=known_details.end,
                time_start=known_details.start,
                transferable_beneficiary=known_details.transferable_beneficiary,
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
    contract_interface.queue_past_events_for_scanning(address=address_list)


async def init_global_contracts(w3: AsyncWeb3, config: EventScannerConfig):
    global event_queue, sn_contrib_factory

    last_event_block = global_db_reader.get_last_fetched_arbitrum_event_block_height()
    start_block = last_event_block + 1 if last_event_block else config.genesis_block
    log.info(f"Last block for an event from the database: {last_event_block}, starting from block {start_block}")

    event_queue = EventQueueManager(w3=w3, log=log, start_block=start_block, max_run_depth=config.ws_max_run_depth, get_logs_cap=config.get_logs_cap)

    if len(config.vesting_contract_details) > 0 :
        await load_vesting_staking_contracts(w3, details=config.vesting_contract_details)

    sn_contrib_factory = ServiceNodeContributionFactory(w3=w3, db_writer=global_db_writer, db_reader=global_db_reader,
                                                        log=log, event_queue=event_queue, start_block=max(config.contrib_factory_start_block, start_block), topic_map=topic_map, event_addresses=event_addresses)
    sn_contrib_factory.queue_past_events_for_scanning(address=config.addr_sn_contrib_factory)
    event_addresses.add(config.addr_sn_contrib_factory)
    for event in sn_contrib_factory.get_events(config.addr_sn_contrib_factory):
        topic_map[event().topic] = (sn_contrib_factory.event_abis[event.name], sn_contrib_factory.handle_event)

    snr = ServiceNodeRewards(w3=w3, db_writer=global_db_writer, db_reader=global_db_reader, log=log, event_queue=event_queue)
    snr.queue_past_events_for_scanning(config.addr_sn_rewards)
    event_addresses.add(config.addr_sn_rewards)
    for event in snr.get_events(config.addr_sn_rewards):
        topic_map[event().topic] = (snr.event_abis[event.name], snr.handle_event)

    rrp = RewardRatePool(w3=w3, db_writer=global_db_writer, log=log, event_queue=event_queue)
    rrp.queue_past_events_for_scanning(
        config.addr_reward_rate_pool
    )
    event_addresses.add(config.addr_reward_rate_pool)
    for event in rrp.get_events(config.addr_reward_rate_pool):
        topic_map[event().topic] = (rrp.event_abis[event.name], rrp.handle_event)

    osu = Ownable2StepUpgradeable(w3=w3, db_writer=global_db_writer, log=log, event_queue=event_queue)
    osu.queue_past_events_for_scanning(
        [config.addr_sn_contrib_factory, config.addr_sn_rewards, config.addr_reward_rate_pool]
    )
    for event in osu.get_events([config.addr_sn_contrib_factory, config.addr_sn_rewards, config.addr_reward_rate_pool]):
        topic_map[event().topic] = (osu.event_abis[event.name], osu._handle_event)


    pu = PausableUpgradeable(w3=w3, db_writer=global_db_writer, log=log, event_queue=event_queue)
    pu.queue_past_events_for_scanning(
        [config.addr_sn_contrib_factory, config.addr_sn_rewards]
    )
    for event in pu.get_events([config.addr_sn_contrib_factory, config.addr_sn_rewards]):
        topic_map[event().topic] = (pu.event_abis[event.name], pu._handle_event)

    ierc = IERC1967(w3=w3, db_writer=global_db_writer, log=log, event_queue=event_queue)
    ierc.queue_past_events_for_scanning(
        [config.addr_sn_contrib_factory, config.addr_sn_rewards, config.addr_reward_rate_pool]
    )
    for event in ierc.get_events([config.addr_sn_contrib_factory, config.addr_sn_rewards, config.addr_reward_rate_pool]):
        topic_map[event().topic] = (ierc.event_abis[event.name], ierc._handle_event)

    if config.ws_watch_token_events:
        log.warning("Watching all token events, this may greatly increase the rescan time (ws_watch_token_events=True)")
        tok = Token(w3=w3, db_writer=global_db_writer, log=log, event_queue=event_queue)
        tok.queue_past_events_for_scanning(config.addr_token)

        for event in tok.get_events(config.addr_token):
           topic_map[event().topic] = (tok.event_abis[event.name], tok.handle_event)

    for topic in topic_map.keys():
        log.info(f"Added topic: {topic}")



async def get_latency(w3: AsyncWeb3):
    """
    Gets the latency of ws requests. In nanoseconds.
    """
    start = time.time_ns()
    await w3.eth.get_block_number()
    return time.time_ns() - start


async def handle_logs(config: EventScannerConfig, handler_context: NewHeadsSubscriptionContext, logs, depth):
    assert depth < 2
    depth += 1
    deploy_topic = sn_contrib_factory.factory(config.addr_sn_contrib_factory).events["NewServiceNodeContributionContract"]().topic
    for event in logs:
        for _topic in event.get("topics", []):
            topic = _topic.to_0x_hex()
            if topic in topic_map:
                abi, handler = topic_map[topic]
                if event["address"] in event_addresses:
                    data = get_event_data(async_w3.codec, abi, event)
                    await handler(data)

                    if topic == deploy_topic:
                        block = event["blockNumber"]
                        contract_address = data.args.get("contributorContract")
                        new_logs = []
                        for new_event in await handler_context.async_w3.eth.get_logs({
                            "fromBlock": block,
                            "toBlock": block,
                            "address": contract_address,
                        }):
                            new_logs.append(new_event)
                        await handle_logs(config, handler_context, new_logs, depth)

next_block = 0
last_block = 0

async def new_heads_handler(config: EventScannerConfig, handler_context: NewHeadsSubscriptionContext):
    global next_block, last_block
    block = handler_context.result["number"]
    if block >= next_block:
        logs = []
        cutoff = last_block + config.get_logs_cap
        was_cut_off = False
        if block > cutoff:
            block = cutoff
            was_cut_off = True

        block = min(block, last_block + config.get_logs_cap)
        for event in await handler_context.async_w3.eth.get_logs({
            "fromBlock": last_block + 1,
            "toBlock": block,
            "address": list(event_addresses),
        }):
            logs.append(event)

        await handle_logs(config, handler_context, logs, 0)
        last_block = block
        next_block = block + (1 if was_cut_off else config.refresh_block_interval)
    


async def monitor_events(config: EventScannerConfig, w3: AsyncWeb3, run_once_as_script=False):
    global last_block, next_block

    # Note: We need the current block just before we subscribe to new heads, this block number is used to fetch all
    # past events up to and including this "current block". Once we get this block we immediately subscribe to new
    # heads, which will start filling up the websocket queue with all the blocks we might miss while we scan for
    # past events. Once past events are scanned for we'll have a large queue of blocks to catch up on, which we will
    # start processing in the subscription queue.
    current_block = await w3.eth.get_block_number()
    await w3.subscription_manager.subscribe(
        [
            NewHeadsSubscription(
                label="new-heads-mainnet",
                handler=partial(new_heads_handler, config)
            )
        ]
    )

    log.info(f"Created {len(w3.subscription_manager.subscriptions)} subscriptions")

    global_db_writer.defer_writing_arbitrum_events = True
    # sn_contrib_factory.add_existing_contribution_contracts(existing_sn_contract_addresses)
    last_block = max(config.contrib_factory_start_block, await event_queue.run(current_block=current_block))

    global_db_writer.defer_writing_arbitrum_events = False
    global_db_writer.write_deferred_arbitrum_events_to_db()

    existing_sn_contract_addresses = global_db_reader.get_arbitrum_event_main_args_by_name(
        "NewServiceNodeContributionContract")
    for address in existing_sn_contract_addresses:
        assert is_checksum_address(
            address), f"Invalid existing NewServiceNodeContributionContract contract address: {address}"
        event_addresses.add(address)

    sn_contrib_factory.add_existing_contribution_contracts(existing_sn_contract_addresses)
    sn_contrib_factory.bootstrap_contribution_contracts()

    global_db_writer.defer_writing_arbitrum_events = True

    last_block = max(config.contrib_factory_start_block, await event_queue.run(current_block=current_block))

    global_db_writer.defer_writing_arbitrum_events = False
    global_db_writer.write_deferred_arbitrum_events_to_db()

    assert len(
        event_queue.event_queue) == 0 and len(
        global_db_writer.deferred_arbitrum_events) == 0, \
        f"Expected all queues to be empty." \
        f"Deferred DB write events: {len(global_db_writer.deferred_arbitrum_events)}"

    latencies = []
    for _ in range(10):
        latencies.append(await get_latency(w3))

    max_latency_ns = max(latencies)
    next_block = last_block + config.refresh_block_interval

    log.info(f"Metrics for ws scanner - latency: {max_latency_ns}, batch size: {config.refresh_block_interval}, last block: {last_block}, next block: {next_block}")

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
        global_db_writer.write_reset_all_rewards_claim_amounts()

    if config.db_reset_contrib_on_startup:
        log.warning("Deleting contrib contracts database on startup (db_reset_contrib_on_startup=True)")
        global_db_writer.delete_all_contrib_contracts_and_contributors()

    if config.reset_vesting_contracts_on_startup:
        log.warning("Deleting vesting contracts database on startup (reset_vesting_contracts_on_startup=True)")
        global_db_writer.delete_all_vesting_contracts()

    log.info("Starting event scanner")
    provider = config.ws_providers[0]
    async for w3 in AsyncWeb3(
            WebSocketProvider(provider, websocket_kwargs={"max_size": config.ws_max_size},
                              request_timeout=300,
                              # one hour of arbitrum blocks in the queue, the high number is required because blocks
                              # pile up in the queue while rescanning the chain.
                              subscription_response_queue_size=3600*4)
    ):
        # TODO: investigate if this properly handles disconnects
        await init_global_contracts(w3, config)
        await asyncio.create_task(monitor_events(config=config, w3=w3, run_once_as_script=config.run_once_as_script))
        if config.run_once_as_script:
            log.info("Exiting websocket disconnection loop as run_once_as_script is True")
            break


def init_ws_event_scanner(config: EventScannerConfig):
    asyncio.run(start(config))
