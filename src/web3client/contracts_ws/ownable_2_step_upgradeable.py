import logging

from eth_typing import ChecksumAddress
from web3 import AsyncWeb3
from web3.contract.async_contract import AsyncContractEvent

from src.staking.write import DBWriterStaking
from src.web3client.contracts_ws.contract_ws import ContractWS
from src.web3client.contracts_ws.contract_utils import queue_past_events_for_scanning
from src.web3client.event_queue_manager import EventQueueManager


class Ownable2StepUpgradeable(ContractWS):
    name = "Ownable2StepUpgradeable"

    def __init__(self, w3: AsyncWeb3, db_writer: DBWriterStaking, log: logging,
                 event_queue: EventQueueManager | None = None):
        super().__init__(self.name, w3, db_writer, log, event_queue)

    def get_events(self, address: ChecksumAddress | list[ChecksumAddress]) -> list[AsyncContractEvent]:
        events = self.factory(address[0] if isinstance(address, list) else address).events
        return [
            events.OwnershipTransferStarted,
            events.OwnershipTransferred,
            events.Initialized,
        ]

    def queue_past_events_for_scanning(self, address: ChecksumAddress | list[ChecksumAddress]):
        event_list = self.get_events(address)

        for event in event_list:
            event.address = address

        return queue_past_events_for_scanning(
            events=event_list,
            event_queue=self.event_queue,
            event_abis=self.event_abis,
            handler_past=self._handle_event,
        )
