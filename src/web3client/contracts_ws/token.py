import logging

from eth_typing import ChecksumAddress
from web3 import AsyncWeb3
from web3.types import EventData
from web3.utils.subscriptions import EthSubscriptionContext

from src.staking.write import DBWriterStaking
from src.web3client.contracts_ws.contract_ws import ContractWS
from src.web3client.contracts_ws.subscription import create_subscriptions
from src.web3client.event_queue_manager import EventQueueManager


class Token(ContractWS):
    name = "SESH"
    decimals = 9

    def __init__(self, w3: AsyncWeb3, db_writer: DBWriterStaking, log: logging,
                 event_queue: EventQueueManager | None = None):
        super().__init__(self.name, w3, db_writer, log, event_queue)

    @staticmethod
    def to_atomic(amount: float | int) -> int:
        """
        Converts a float or int to an atomic amount
        """
        return int(amount * (10 ** Token.decimals))

    @staticmethod
    def from_atomic(amount: int) -> float:
        """
        Converts an atomic amount to a float
        """
        return amount / (10 ** Token.decimals)

    @staticmethod
    def get_main_arg(event: EventData):
        match event.event:
            case "Approval":
                return event.args.owner
            case "Transfer":
                return event.args.to
            case _:
                return None

    async def handle_event(self, event: EventData):
        main_arg = Token.get_main_arg(event)
        assert main_arg is not None
        return await self._handle_event(event, main_arg=main_arg)

    async def handle_event_sub(self, event: EthSubscriptionContext):
        return await self.handle_event(self._parse_event(event))

    def create_subscriptions(self, address: ChecksumAddress):
        events = self.factory(address).events
        return create_subscriptions(
            events=[
                events.Transfer,
                events.Approval,
            ],
            event_queue=self.event_queue,
            event_abis=self.event_abis,
            handler_sub=self.handle_event_sub,
            handler_past=self.handle_event,
        )
