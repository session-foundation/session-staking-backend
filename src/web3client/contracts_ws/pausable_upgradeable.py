import logging

from eth_typing import ChecksumAddress
from web3 import AsyncWeb3

from src.staking.write import DBWriterStaking
from src.web3client.contracts_ws.contract_ws import ContractWS
from src.web3client.contracts_ws.subscription import create_subscriptions
from src.web3client.event_queue_manager import EventQueueManager


class PausableUpgradeable(ContractWS):
    name = "PausableUpgradeable"

    def __init__(self, w3: AsyncWeb3, db_writer: DBWriterStaking, log: logging,
                 event_queue: EventQueueManager | None = None):
        super().__init__(self.name, w3, db_writer, log, event_queue)

    def create_subscriptions(self, address: ChecksumAddress | list[ChecksumAddress]):
        events = self.factory(address[0] if isinstance(address, list) else address).events
        event_list = [
            events.Paused,
            events.Unpaused,
        ]

        for event in event_list:
            event.address = address

        return create_subscriptions(
            events=event_list,
            event_queue=self.event_queue,
            event_abis=self.event_abis,
            handler_sub=self._handle_event_sub,
            handler_past=self._handle_event,
        )
