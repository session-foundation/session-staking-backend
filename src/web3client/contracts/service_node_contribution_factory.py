from ..client import Web3Client
from ..contracts.contract import ContractInterface
from ..event_scanner import EventScanner


class ServiceNodeContributionFactory(ContractInterface):
    abi_name = "ServiceNodeContributionFactory"

    def __init__(self, web3_client: Web3Client, contract_address: str, scanner_safety_blocks: int, scan_start_chunk_size: int):
        super().__init__(web3_client, contract_address, ServiceNodeContributionFactory.abi_name)
        self.event_scanner = EventScanner(
            provider_url=web3_client.provider_url,
            events=[
                self.contract.events.NewServiceNodeContributionContract,
            ],
            filters={"address": self.contract_address},
            # How many maximum blocks at the time we request from JSON-RPC
            # and we are unlikely to exceed the response size limit of the JSON-RPC server
            max_chunk_scan_size=10_000_000,
            safety_blocks=scanner_safety_blocks,
            optimal_chunk_size=scan_start_chunk_size
        )
