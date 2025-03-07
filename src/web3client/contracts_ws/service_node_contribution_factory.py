import logging

from eth_typing import ChecksumAddress
from web3 import AsyncWeb3
from web3.types import EventData
from web3.utils.subscriptions import EthSubscriptionContext

from src.staking.read import DBReaderStaking
from src.staking.write import DBWriterStaking
from src.web3client.contracts_ws.contract_ws import ContractWS
from src.web3client.contracts_ws.service_node_contribution import ServiceNodeContribution
from src.web3client.contracts_ws.subscription import create_subscriptions
from src.web3client.event_queue_manager import EventQueueManager


class ServiceNodeContributionFactory(ContractWS):
    name = "ServiceNodeContributionFactory"
    event_names = ["NewServiceNodeContributionContract"]

    def __init__(self, w3: AsyncWeb3, db_writer: DBWriterStaking, db_reader: DBReaderStaking, log: logging,
                 event_queue: EventQueueManager | None = None):
        super().__init__(self.name, w3, db_writer, log, event_queue)
        self.service_node_contribution_contract = ServiceNodeContribution(w3=w3, db_writer=db_writer,
                                                                          db_reader=db_reader, log=log,
                                                                          event_queue=self.event_queue)
        self.bootstrap_contribution_contract_addresses = []

    def add_existing_contribution_contracts(self, addresses: list[str]):
        self.bootstrap_contribution_contract_addresses.extend(addresses)

    def bootstrap_contribution_contracts(self):
        if len(self.bootstrap_contribution_contract_addresses) == 0:
            self.log.warning("No bootstrap contribution contract addresses found")
            return
        self.log.info(f"Bootstrapping {len(self.bootstrap_contribution_contract_addresses)} contribution contracts")
        self.service_node_contribution_contract.create_subscriptions(
            address=self.bootstrap_contribution_contract_addresses)

    async def handle_event(self, event: EventData, is_bootstrap: bool = True):
        address = event.args.get("contributorContract")
        await self._handle_event(event, main_arg=address)
        self.db_writer.write_new_contribution_contract(address, event.args.get("operator"))
        if is_bootstrap:
            self.bootstrap_contribution_contract_addresses.append(address)
        else:
            self.service_node_contribution_contract.create_subscriptions(address=address)

    async def handle_event_sub(self, event: EthSubscriptionContext):
        return await self.handle_event(self._parse_event(event), is_bootstrap=False)

    def create_subscriptions(self, address: ChecksumAddress):
        events = self.factory(address).events
        return create_subscriptions(
            events=[events[name] for name in self.event_names],
            event_queue=self.event_queue,
            event_abis=self.event_abis,
            handler_sub=self.handle_event_sub,
            handler_past=self.handle_event,
        )
