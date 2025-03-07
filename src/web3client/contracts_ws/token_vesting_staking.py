import logging

from eth_typing import ChecksumAddress
from web3 import AsyncWeb3
from web3.contract import Contract
from web3.types import EventData
from web3.utils.subscriptions import EthSubscriptionContext

from src.staking.write import DBWriterStaking
from src.web3client.contracts_ws.contract_ws import ContractWS
from src.web3client.contracts_ws.subscription import create_subscriptions
from src.web3client.event_queue_manager import EventQueueManager


class TokenVestingStaking(ContractWS):
    name = "TokenVestingStaking"

    def __init__(self, w3: AsyncWeb3, db_writer: DBWriterStaking, log: logging,
                 event_queue: EventQueueManager | None = None):
        super().__init__(self.name, w3, db_writer, log, event_queue)

    async def handle_event(self, event: EventData):
        await self._handle_event(event, main_arg=event.address)

    async def handle_event_sub(self, event: EthSubscriptionContext):
        await self.handle_event(self._parse_event(event))

    def create_subscriptions(self, address: ChecksumAddress | list[ChecksumAddress]):
        events = self.factory(address[0] if isinstance(address, list) else address).events
        event_list = [
            events.TokensReleased,
            events.TokenVestingRevoked,
            events.TokensRevokedReleased,
            events.BeneficiaryTransferred,
            events.RevokerTransferred,
        ]

        for event in event_list:
            event.address = address

        return create_subscriptions(
            events=events,
            event_queue=self.event_queue,
            event_abis=self.event_abis,
            handler_sub=self.handle_event_sub,
            handler_past=self.handle_event,
        )

    batch_items = 9

    async def batch_get_details(self, addresses: list[ChecksumAddress], token_contract: Contract):
        async with self.w3.batch_requests() as batch:
            for address in addresses:
                contract = self.factory(address)
                batch.add(contract.functions.beneficiary())
                batch.add(contract.functions.revoker())
                batch.add(token_contract.functions.balanceOf(address))
                batch.add(contract.functions.transferableBeneficiary())
                batch.add(contract.functions.start())
                batch.add(contract.functions.end())
                batch.add(contract.functions.SESH())
                batch.add(contract.functions.rewardsContract())
                batch.add(contract.functions.snContribFactory())

            responses = await batch.async_execute()
            assert len(responses) == len(addresses) * TokenVestingStaking.batch_items

            return responses
