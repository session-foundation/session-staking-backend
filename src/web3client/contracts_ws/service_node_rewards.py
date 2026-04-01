import logging

from eth_typing import ChecksumAddress
from web3 import AsyncWeb3
from web3.contract.async_contract import AsyncContractEvent
from web3.types import EventData
from web3.utils.subscriptions import EthSubscriptionContext

from src.staking.read import DBReaderStaking
from src.staking.write import DBWriterStaking
from src.web3client.contracts_ws.contract_ws import ContractWS
from src.web3client.contracts_ws.contract_utils import queue_past_events_for_scanning
from src.web3client.event_queue_manager import EventQueueManager

def handle_claim(event: EventData, db_writer: DBWriterStaking, db_reader: DBReaderStaking, log: logging):
    address = event.args.recipientAddress
    amount = event.args.amount

    try:
        reward_info = db_reader.get_rewards_info_for_address(address)
    except Exception as e:
        return

    assert reward_info is not None, f"Rewards info not found for address {address}"

    claimed_stakes = reward_info.claimed_stakes
    claimed_rewards = reward_info.claimed_rewards

    remaining = amount
    stakes_avail = reward_info.lifetime_unlocked_stakes - reward_info.lifetime_liquidated_stakes - claimed_stakes
    if remaining > stakes_avail:
        remaining -= stakes_avail
        claimed_stakes += stakes_avail
    else:
        claimed_stakes += remaining
        remaining = 0

    rewards_avail = reward_info.lifetime_rewards - claimed_rewards
    if remaining > rewards_avail:
        remaining -= rewards_avail
        claimed_rewards += rewards_avail
    else:
        claimed_rewards += remaining
        remaining = 0

    #    assert remaining == 0, f"Remaining rewards {remaining} is not equal to 0"

    db_writer.write_update_rewards_claim_amounts(address, claimed_stakes, claimed_rewards)


class ServiceNodeRewards(ContractWS):
    name = "ServiceNodeRewards"

    def __init__(self, w3: AsyncWeb3, db_writer: DBWriterStaking, db_reader: DBReaderStaking, log: logging,
                 event_queue: EventQueueManager | None = None):
        super().__init__(self.name, w3, db_writer, log, event_queue)
        self.db_reader = db_reader

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

        if event.event == "RewardsClaimed":
            handle_claim(event, self.db_writer, self.db_reader, self.log)

        return await self._handle_event(event, main_arg=main_arg)

    async def handle_event_sub(self, event: EthSubscriptionContext):
        return await self.handle_event(self._parse_event(event))

    def get_events(self, address: ChecksumAddress) -> list[AsyncContractEvent]:
        events = self.factory(address).events
        return [
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
        ]

    def queue_past_events_for_scanning(self, address: ChecksumAddress):
        return queue_past_events_for_scanning(
            events=self.get_events(address),
            event_queue=self.event_queue,
            event_abis=self.event_abis,
            handler_past=self.handle_event,
        )
