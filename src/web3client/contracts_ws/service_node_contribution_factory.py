import logging

from eth_typing import ChecksumAddress
from web3 import AsyncWeb3
from web3.contract.async_contract import AsyncContractEvent
from web3.types import EventData
from web3.utils.subscriptions import EthSubscriptionContext

from src.staking.read import DBReaderStaking
from src.staking.write import DBWriterStaking
from src.util.parse import parse_ed25519_pubkey
from src.web3client.contracts_ws.contract_ws import ContractWS
from src.web3client.contracts_ws.service_node_contribution import ServiceNodeContribution
from src.web3client.contracts_ws.contract_utils import queue_past_events_for_scanning
from src.web3client.event_queue_manager import EventQueueManager


class ServiceNodeContributionFactory(ContractWS):
    name = "ServiceNodeContributionFactory"
    event_names = ["NewServiceNodeContributionContract"]

    def __init__(self, w3: AsyncWeb3, db_writer: DBWriterStaking, db_reader: DBReaderStaking, log: logging,
                 event_queue: EventQueueManager | None = None, start_block: int = 0, topic_map = None, event_addresses = None):
        super().__init__(self.name, w3, db_writer, log, event_queue)
        self.service_node_contribution_contract = ServiceNodeContribution(w3=w3, db_writer=db_writer,
                                                                          db_reader=db_reader, log=log,
                                                                          event_queue=self.event_queue)
        self.bootstrap_contribution_contract_addresses = []
        self.start_block = start_block
        self.topic_map = topic_map
        self.event_addresses = event_addresses

    def add_existing_contribution_contracts(self, addresses: list[str]):
        self.bootstrap_contribution_contract_addresses.extend(addresses)

    def bootstrap_contribution_contracts(self):
        if len(self.bootstrap_contribution_contract_addresses) == 0:
            self.log.warning("No bootstrap contribution contract addresses found")
            return
        self.log.info(f"Bootstrapping {len(self.bootstrap_contribution_contract_addresses)} contribution contracts from block {self.start_block}")
        self.service_node_contribution_contract.queue_past_events_for_scanning(
            address=self.bootstrap_contribution_contract_addresses, start_block=self.start_block)
        events = self.service_node_contribution_contract.get_events(self.bootstrap_contribution_contract_addresses[0])
        for address in self.bootstrap_contribution_contract_addresses:
            self.event_addresses.add(address)
        for event in events:
            existing_topic = self.topic_map.get(event().topic)
            if existing_topic is None:
                print(f"Adding topic f{event.name}: {event().topic}")
                self.topic_map[event().topic] = (self.service_node_contribution_contract.event_abis[event.name], self.service_node_contribution_contract.handle_event)


    async def handle_event(self, event: EventData):
        address = event.args.get("contributorContract")
        await self._handle_event(event, main_arg=address)
        self.db_writer.write_new_contribution_contract(address, event.args.get("operator"), parse_ed25519_pubkey(event.args.get("serviceNodePubkey")))
        events = self.service_node_contribution_contract.get_events(address)
        self.event_addresses.add(address)
        for event in events:
            topic = event().topic
            existing_topic = self.topic_map.get(topic)
            if existing_topic is None:
                self.log.debug(f"Adding new topic {topic}")
                self.topic_map[topic] = (self.service_node_contribution_contract.event_abis[event.name], self.service_node_contribution_contract.handle_event)


    async def handle_event_bootstrap(self, event: EventData):
        address = event.args.get("contributorContract")
        await self._handle_event(event, main_arg=address)
        self.db_writer.write_new_contribution_contract(address, event.args.get("operator"), parse_ed25519_pubkey(event.args.get("serviceNodePubkey")))
        self.bootstrap_contribution_contract_addresses.append(address)


    async def handle_event_sub(self, event: EthSubscriptionContext):
        return await self.handle_event(self._parse_event(event))

    def get_events(self, address: ChecksumAddress) -> list[AsyncContractEvent]:
        events = self.factory(address).events
        return [events[name] for name in self.event_names]

    def queue_past_events_for_scanning(self, address: ChecksumAddress):
        return queue_past_events_for_scanning(
            events=self.get_events(address),
            event_queue=self.event_queue,
            event_abis=self.event_abis,
            handler_past=self.handle_event_bootstrap,
            start_block=self.start_block,
        )
