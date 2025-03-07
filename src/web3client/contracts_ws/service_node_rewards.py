import logging

from eth_typing import ChecksumAddress
from web3 import AsyncWeb3
from web3.types import EventData
from web3.utils.subscriptions import EthSubscriptionContext

from src.staking.write import DBWriterStaking
from src.web3client.contracts_ws.contract_ws import ContractWS
from src.web3client.contracts_ws.subscription import create_subscriptions
from src.web3client.event_queue_manager import EventQueueManager


class ServiceNodeRewards(ContractWS):
    name = "ServiceNodeRewards"

    def __init__(self, w3: AsyncWeb3, db_writer: DBWriterStaking, log: logging,
                 event_queue: EventQueueManager | None = None):
        super().__init__(self.name, w3, db_writer, log, event_queue)

    @staticmethod
    def get_main_arg(event: EventData):
        match event.event:
            case "RewardsClaimed":
                return event.args.recipientAddress
            case "StakingRequirementUpdated":
                return event.args.newRequirement
            case "ClaimThresholdUpdated":
                return event.args.newThreshold
            case "ClaimCycleUpdated":
                return event.args.newValue
            case "LiquidationRatiosUpdated":
                return event.args.liquidatorRatio
            case "BLSNonSignerThresholdMaxUpdated":
                return event.args.newMax
            case _:
                return event.args.serviceNodeID

    async def handle_event(self, event: EventData):
        main_arg = ServiceNodeRewards.get_main_arg(event)
        assert main_arg is not None
        return await self._handle_event(event, main_arg=main_arg)

    async def handle_event_sub(self, event: EthSubscriptionContext):
        return await self.handle_event(self._parse_event(event))

    def create_subscriptions(self, address: ChecksumAddress):
        events = self.factory(address).events
        return create_subscriptions(
            events=[
                events.NewSeededServiceNode,
                events.NewServiceNodeV2,
                events.ServiceNodeExitRequest,
                events.ServiceNodeExit,
                events.ServiceNodeLiquidated,
                events.RewardsClaimed,
                events.StakingRequirementUpdated,
                events.ClaimThresholdUpdated,
                events.ClaimCycleUpdated,
                events.LiquidationRatiosUpdated,
                events.BLSNonSignerThresholdMaxUpdated,
            ],
            event_queue=self.event_queue,
            event_abis=self.event_abis,
            handler_sub=self.handle_event_sub,
            handler_past=self.handle_event,
        )
