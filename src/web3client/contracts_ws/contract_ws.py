import logging

from web3 import AsyncWeb3
from web3.types import EventData
from web3.utils.subscriptions import EthSubscriptionContext

from src.staking.write import DBWriterStaking
from src.web3client.contract_factory import ContractFactory
from src.web3client.contracts_ws.contract_utils import parse_event, write_event_to_db
from src.web3client.event_queue_manager import EventQueueManager


class ContractWS:
    def __init__(self, name: str, w3: AsyncWeb3, db_writer: DBWriterStaking, log: logging,
                 event_queue: EventQueueManager | None = None):
        self.w3 = w3
        self.log = log
        self.factory = ContractFactory(w3).get(name)
        self.db_writer = db_writer
        self.event_abis = {}
        self.event_queue = event_queue

    def _parse_event(self, event: EthSubscriptionContext):
        return parse_event(self.event_abis, event)

    async def _handle_event(self, event: EventData, main_arg: str | None = None):
        self.log.debug(f"New {event.event}: {event.args}")
        if main_arg is None:
            main_arg = event.address
        write_event_to_db(self.db_writer, event, main_arg=main_arg)

    async def _handle_event_sub(self, event: EthSubscriptionContext):
        await self._handle_event(self._parse_event(event))
