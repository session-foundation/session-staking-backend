from web3 import Web3
from abi_manager import ABIManager

class ServiceNodeContributionFactory:
    def __init__(self, provider_url, contract_address):
        """
        Initialize the connection to the ServiceNodeContributionFactory contract.

        :param provider_url: URL of the Ethereum node to connect to.
        :param contract_address: Address of the deployed ServiceNodeContributionFactory contract.
        """
        self.web3 = Web3(Web3.HTTPProvider(provider_url))
        self.contract_address = Web3.to_checksum_address(contract_address)
        manager = ABIManager()
        abi = manager.load_abi('ServiceNodeContributionFactory')
        self.contract = self.web3.eth.contract(address=self.contract_address, abi=abi)
        self.last_contribution_event_height = 0

    def max_contributors(self):
        """
        Calls the view function to get the maximum number of contributors.

        :return: Maximum number of contributors as integer.
        """
        return self.contract.functions.maxContributors().call()

    def designated_token(self):
        """
        Calls the view function to get the designated token address.

        :return: Address of the designated token as string.
        """
        return self.contract.functions.SENT().call()

    def get_new_contribution_contract_events(self, from_block='latest'):
        """
        Retrieves the events of new contribution contracts deployed.

        :param from_block: The block number to start looking for events.
        :return: List of events.
        """
        return self.contract.events.NewServiceNodeContributionContract.get_logs(from_block=from_block)

    def get_latest_contribution_contract_events(self):
        """
        Retrieves the latest events of new contribution contracts deployed. keeping track of when last called

        :return: List of events.
        """
        events = self.get_new_contribution_contract_events(self.last_contribution_event_height)
        self.last_contribution_event_height = self.web3.eth.block_number
        return events

# Example usage:
# factory_interface = ServiceNodeContributionFactory('http://127.0.0.1:8545', '0x...')
# max_contributors = factory_interface.max_contributors()
# designated_token = factory_interface.designated_token()
# new_contribution_contracts = factory_interface.get_new_contribution_contract_events()

