from collections.abc import Callable

from web3._utils.events import get_event_data
from web3.contract.async_contract import AsyncContractEvent
from web3.types import EventData
from web3.utils.subscriptions import LogsSubscription, EthSubscriptionContext

from src.staking.write import DBWriterStaking
from src.web3client.event_queue_manager import EventQueueManager
from src.web3client.event_scanner import ProcessedEvent


def create_subscriptions(
        events: list[AsyncContractEvent],
        event_queue: EventQueueManager,
        handler_sub: Callable,
        handler_past: Callable = None,
        event_abis: dict[str, any] = None
):
    assert isinstance(event_queue, EventQueueManager), "event_queue must be an instance of EventQueueManager"
    for event in events:
        label_address = event.address[0] if isinstance(event.address, list) else event.address
        label = f"{event.name}_{label_address}"

        event_queue.add(
            event=event,
            handler=handler_past,
            sub=LogsSubscription(
                label=label,
                address=event.address,
                topics=[event().topic],
                handler=handler_sub,
            ),
        )

        if event.name not in event_abis:
            event_abis[event.name] = event._get_event_abi()


def parse_event(event_abis, event: EthSubscriptionContext):
    result = event.result
    name = event.subscription.label

    if "_" in name:
        name = name.split("_")[0]

    abi = event_abis[name]
    data = get_event_data(event.async_w3.codec, abi, result)
    return data


def create_processed_event(event: EventData, main_arg: str | None = None):
    return ProcessedEvent(
        name=event.event,
        args=event.args,
        log_index=event.logIndex,
        block=event.blockNumber,
        main_arg=main_arg,
        tx=event.transactionHash.hex()
    )


def write_event_to_db(db_writer: DBWriterStaking, event: EventData, main_arg: str | None = None):
    event = create_processed_event(event, main_arg=main_arg)
    db_writer.write_arbitrum_event_to_db(event)
