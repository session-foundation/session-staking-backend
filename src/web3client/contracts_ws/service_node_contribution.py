import logging
from dataclasses import dataclass

from eth_typing import ChecksumAddress
from web3 import AsyncWeb3
from web3.contract.async_contract import AsyncContractEvent
from web3.types import EventData
from web3.utils.subscriptions import EthSubscriptionContext

from src.staking.read import DBReaderStaking
from src.staking.write import DBWriterStaking
from src.util.parse import parse_ed25519_pubkey, parse_bls_pubkey
from src.web3client.contracts_ws.contract_ws import ContractWS
from src.web3client.contracts_ws.contract_utils import queue_past_events_for_scanning, create_processed_event
from src.web3client.event_queue_manager import EventQueueManager


@dataclass
class ContributionContractContributor:
    address: str = None
    amount: int = 0
    beneficiary: str = None
    reserved: int = 0


class ContributionContract:
    def __init__(self, address, log, db_writer: DBWriterStaking, db_reader: DBReaderStaking = None):
        self.log = log
        self.db_writer = db_writer
        self.address = address

        contributors = db_reader.get_contribution_contract_contributors(address) if db_reader else []

        self._contributors = {}
        if len(contributors) > 0:
            for contributor in contributors:
                self._contributors[contributor.address] = contributor
        self.log.debug(f"Initialized {self.address} with Contributors: {self._contributors}")

    def update_status(self, status: int):
        self.log.debug(f"Updating status of {self.address} to {status}")
        self.db_writer.write_update_contribution_contract_status(self.address, status)

    def update_manual_finalize(self, new_value: bool):
        self.log.debug(f"Updating manual finalize of {self.address} to {new_value}")
        self.db_writer.write_update_contribution_contract_manual_finalize(self.address, new_value)

    def update_fee(self, new_fee: int):
        self.log.debug(f"Updating fee of {self.address} to {new_fee}")
        self.db_writer.write_update_contribution_contract_fee(self.address, new_fee)

    def update_pubkeys(self, new_bls_pubkey: dict, new_ed25519_pubkey: int):
        self.log.debug(f"Updating pubkeys of {self.address} to {new_bls_pubkey}, {new_ed25519_pubkey}")
        if new_bls_pubkey is None:
            self.log.warning(f"No new BLS pubkey found for {self.address}")
            return
        if new_ed25519_pubkey is None:
            self.log.warning(f"No new Ed25519 pubkey found for {self.address}")
            return

        pubkey_bls = parse_bls_pubkey(new_bls_pubkey)
        service_node_pubkey = parse_ed25519_pubkey(new_ed25519_pubkey)
        self.db_writer.write_update_contribution_contract_pubkeys(self.address, pubkey_bls, service_node_pubkey)

    def _upsert_contributor(self, address: str, beneficiary: str | None):
        self._contributors.setdefault(address, ContributionContractContributor(address=address, beneficiary=beneficiary))

    def update_contributor_new_contribution(self, address: str, beneficiary: str, amount: int):
        self.log.debug(f"Updating contributor add {address} with beneficiary {beneficiary} and amount {amount}")
        self._upsert_contributor(address, beneficiary)
        self._contributors[address].address = address
        self._contributors[address].beneficiary = beneficiary
        self._contributors[address].amount += amount
        self.db_writer.write_update_contribution_contract_contributor(self.address, self._contributors[address])

    def update_contributor_withdraw_contribution(self, address: str, amount: int):
        self.log.debug(f"Updating contributor remove {address} with amount {amount}")
        if address in self._contributors:
            self._contributors[address].amount -= amount
            if self._contributors[address].amount == 0:
                del self._contributors[address]
                self.db_writer.write_delete_contribution_contract_contributor(self.address, address)
            else:
                self.db_writer.write_update_contribution_contract_contributor(self.address, self._contributors[address])
        else:
            self.log.warning(f"No contributor found for address {address} to withdraw {amount}")

    def update_contributor_beneficiary(self, address: str, beneficiary: str):
        self.log.debug(f"Updating contributor beneficiary {address} to {beneficiary}")
        self._upsert_contributor(address, beneficiary)
        self._contributors[address].beneficiary = beneficiary
        self.db_writer.write_update_contribution_contract_contributor(self.address, self._contributors[address])

    def update_reserved_contributors(self, reserved_contributors: list[dict[str, str]]):
        self.log.debug(f"Updating reserved contributors {reserved_contributors}")
        for reserved_contributor in reserved_contributors:
            address = reserved_contributor.get("addr")
            reserved_amount = reserved_contributor.get("amount")
            self._upsert_contributor(address, None)
            self._contributors[address].reserved = reserved_amount
            self.db_writer.write_update_contribution_contract_contributor(self.address, self._contributors[address])

    def update_reset(self):
        self.log.debug(f"Updating reset for {self.address}")
        self._contributors = {}
        self.db_writer.write_delete_all_contribution_contract_contributors(self.address)
        self.update_status(0)

    def process_event(self, raw_event: EventData):
        event = create_processed_event(raw_event, main_arg=self.address)
        self.log.debug(f"Processing sn event: {event}")
        match event.name:
            case "OpenForPublicContribution":
                return self.update_status(1)

            case "Filled":
                return self.update_status(2)

            case "Finalized":
                return self.update_status(3)

            case "NewContribution":
                return self.update_contributor_new_contribution(event.args.get("contributor"), event.args.get("beneficiary"), event.args.get("amount"))

            case "WithdrawContribution":
                return self.update_contributor_withdraw_contribution(event.args.get("contributor"),
                                                                     event.args.get("amount"))

            case "UpdateStakerBeneficiary":
                return self.update_contributor_beneficiary(event.args.get("staker"), event.args.get("newBeneficiary"))

            case "UpdateManualFinalize":
                return self.update_manual_finalize(event.args.get("newValue"))

            case "UpdateFee":
                return self.update_fee(event.args.get("newFee"))

            case "UpdatePubkeys":
                return self.update_pubkeys(event.args.get("newBLSPubkey"), event.args.get("newEd25519Pubkey"))

            case "UpdateReservedContributors":
                return self.update_reserved_contributors(event.args.get("newReservedContributors"))

            case "Reset":
                return self.update_reset()

            case _:
                return self.log.warning(f"Unknown event to process: {event}")


tracked_contracts: dict[str, ContributionContract] = {}


class ServiceNodeContribution(ContractWS):
    name = "ServiceNodeContribution"
    event_names = [
        "Finalized",
        "NewContribution",
        "OpenForPublicContribution",
        "Filled",
        "WithdrawContribution",
        "UpdateStakerBeneficiary",
        "UpdateManualFinalize",
        "UpdateFee",
        "UpdatePubkeys",
        "UpdateReservedContributors",
        "Reset",
    ]

    def __init__(self, w3: AsyncWeb3, db_writer: DBWriterStaking, db_reader: DBReaderStaking, log: logging,
                 event_queue: EventQueueManager | None = None):
        super().__init__(self.name, w3, db_writer, log, event_queue)
        self.db_reader = db_reader

    async def handle_event(self, event: EventData):
        await self._handle_event(event, main_arg=event.address)
        tracked_contracts.setdefault(
            event.address,
            ContributionContract(address=event.address, log=self.log, db_writer=self.db_writer,
                                 db_reader=self.db_reader)
        )
        tracked_contracts[event.address].process_event(event)

    async def handle_event_sub(self, event: EthSubscriptionContext):
        return await self.handle_event(self._parse_event(event))


    def get_events(self, address: ChecksumAddress) -> list[AsyncContractEvent]:
        events = self.factory(address[0] if isinstance(address, list) else address).events
        return [events[name] for name in self.event_names]

    def queue_past_events_for_scanning(self, address: ChecksumAddress | list[ChecksumAddress], start_block: int = 0):
        event_list = self.get_events(address)

        for event in event_list:
            event.address = address

        return queue_past_events_for_scanning(
            events=event_list,
            event_queue=self.event_queue,
            event_abis=self.event_abis,
            handler_past=self.handle_event,
            start_block=start_block,
        )

    batch_items = 7
    # TODO: use this to get details for old contracts
    async def batch_get_details(self, addresses: list[ChecksumAddress]):
        chunk_size = 100
        chunks = [addresses[i: i + chunk_size] for i in range(0, len(addresses), chunk_size)]
        responses = []
        for chunk in chunks:
            assert len(chunk) <= chunk_size, "Expected chunk size <= {} got {}".format(chunk_size, len(chunk))
            async with self.w3.batch_requests() as batch:
                for address in chunk:
                    contract = self.factory(address)
                    batch.add(contract.functions.serviceNodeParams())
                    batch.add(contract.functions.operator())
                    batch.add(contract.functions.blsPubkey())
                    batch.add(contract.functions.getContributions())
                    batch.add(contract.functions.status())
                    batch.add(contract.functions.manualFinalize())
                    batch.add(contract.functions.getReserved())

                res = await batch.async_execute()
                if len(res) == 1:
                    self.log.warning(res[0])
                assert len(res) == len(
                    chunk) * ServiceNodeContribution.batch_items, f"Expected {len(chunk) * ServiceNodeContribution.batch_items} responses, got {len(res)}"
                responses.extend(res)

        assert len(responses) == len(
            addresses) * ServiceNodeContribution.batch_items, f"Expected {len(addresses) * ServiceNodeContribution.batch_items} responses, got {len(responses)}"

        return responses
