from web3 import Web3
from abi_manager import ABIManager

class ContributorContractInterface:
    """ Parent class to handle Web3 connection and load ABI for contracts. """

    def __init__(self, provider_url):
        """
        Initialize the connection to the Ethereum provider.
        :param provider_url: URL of the Ethereum node to connect to.
        """
        self.web3 = Web3(Web3.HTTPProvider(provider_url))
        manager = ABIManager()
        self.abi = manager.load_abi('ServiceNodeContribution')

    def get_contract_instance(self, contract_address):
        """
        Create an instance of a contract at a given address.
        :param contract_address: Address of the contract to interact with.
        :return: Web3 Contract object.
        """
        contract = self.web3.eth.contract(address=Web3.to_checksum_address(contract_address), abi=self.abi)
        return ServiceNodeContribution(contract)

class ServiceNodeContribution:
    """ Child class to interact with specific Service Node Contribution contracts. """

    def __init__(self, contract):
        """
        Initialize the contract interaction class with the contract.
        :param contract: Web3 Contract object.
        """
        self.contract = contract

    def get_contributor_contribution(self, contributor_address):
        """
        Get the contribution amount of a specific contributor.
        :param contributor_address: Address of the contributor.
        :return: Contribution amount of the specified contributor.
        """
        return self.contract.functions.contributions(Web3.to_checksum_address(contributor_address)).call()

    def is_finalized(self):
        """
        Check if the service node is finalized.
        :return: True if the service node is finalized, otherwise False.
        """
        return self.contract.functions.finalized().call()

    def is_cancelled(self):
        """
        Check if the service node has been cancelled.
        :return: True if the service node has been cancelled, otherwise False.
        """
        return self.contract.functions.cancelled().call()

    def total_contribution(self):
        """
        Get the total amount of contributions received.
        :return: Total contributions amount.
        """
        return self.contract.functions.totalContribution().call()

    def contributor_count(self):
        """
        Get the number of contributors.
        :return: Number of contributors.
        """
        return len(self.contract.functions.contributorAddresses().call())

    def minimum_contribution(self):
        """
        Get the minimum contribution required.
        :return: Minimum contribution amount.
        """
        return self.contract.functions.minimumContribution().call()

    def get_bls_pubkey(self):
        """
        Get the BLS public key.
        :return: BLS public key, in hex.
        """
        pks = self.contract.functions.blsPubkey().call()
        return "0x{:0128x}".format((pks[0] << 256) + pks[1])

    def get_service_node_params(self):
        """
        Get the parameters of the service node.
        :return: Dictionary containing service node parameters.
        """
        params = self.contract.functions.serviceNodeParams().call()
        return {
                'serviceNodePubkey': f"{params[0]:032x}",
                'serviceNodeSignature': f"{params[1]:032x}{params[2]:032x}",
                'fee': params[3]
        }

    def get_operator(self):
        """
        returns the service node operator
        """
        contributor_addresses = self.get_contributor_addresses()
        return contributor_addresses[0]


    def get_contributor_addresses(self):
        """
        Get the list of contributor addresses.
        :return: List of addresses of contributors.
        """
        addresses = []
        for index in range(self.contract.functions.maxContributors().call()):
            try:
                addresses.append(self.contract.functions.contributorAddresses(index).call())
            except:
                continue

        return addresses

    def get_individual_contributions(self):
        """
        Retrieve contributions for each contributor.
        :return: Dictionary mapping contributor addresses to their contributions.
        """
        contributor_addresses = self.get_contributor_addresses()
        contributions = {
            address: self.get_contributor_contribution(address) for address in contributor_addresses
        }
        return contributions

# Example usage:
# provider_url = 'http://127.0.0.1:8545'
# contract_address = '0x...'

# contract_interface = ContributorContractInterface(provider_url)
# service_node = contract_interface.get_contract_instance(contract_address)

# Fetch and display data from the contract
# print("Total Contribution:", service_node.total_contribution())
# print("Is Finalized:", service_node.is_finalized())
# print("Is Cancelled:", service_node.is_cancelled())
# print("Minimum Contribution Required:", service_node.minimum_contribution())
