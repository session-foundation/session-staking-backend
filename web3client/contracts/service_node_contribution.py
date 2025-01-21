import time
from dataclasses import dataclass

from web3 import Web3
from web3client.client import Web3Client
from web3client.contracts.contract import ContractInterface


class ServiceNodeContributionInterface(ContractInterface):
    abi_name = "ServiceNodeContribution"

    def __init__(self, web3_client: Web3Client, contract_address: str):
        super().__init__(web3_client, contract_address, ServiceNodeContributionInterface.abi_name)

    def get_contributor_contribution(self, contributor_address):
        """
        Get the contribution amount of a specific contributor.
        :param contributor_address: Address of the contributor.
        :return: Contribution amount of the specified contributor.
        """
        return self.contract.functions.contributions(
            Web3.to_checksum_address(contributor_address)
        ).call()

    def status(self):
        """
        Check if the service node is finalized.
        :return: True if the service node is finalized, otherwise False.
        """
        return self.contract.functions.status().call()

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
            "serviceNodePubkey": f"{params[0]:032x}",
            "serviceNodeSignature": f"{params[1]:032x}{params[2]:032x}",
            "fee": params[3],
        }

    def get_operator(self):
        """
        returns the service node operator
        """
        return self.contract.functions.operator().call()

    def get_contributions(self):
        # (address[] memory addrs, address[] memory beneficiaries, uint256[] memory contribs)
        contributions = self.contract.functions.getContributions().call()
        addresses = contributions[0]
        beneficiaries = contributions[1]
        contributions = contributions[2]

        contributions_list = []
        for i in range(len(addresses)):
            contributions_list.append(
                {
                    "address": addresses[i],
                    "amount": contributions[i],
                    "beneficiary": beneficiaries[i],
                }
            )
        return contributions_list

    @staticmethod
    def add_details_fetch_to_batch_added_batches():
        return 6

    def add_details_fetch_to_batch(self, batch):
        batch.add(self.contract.functions.serviceNodeParams())
        batch.add(self.contract.functions.operator())
        batch.add(self.contract.functions.blsPubkey())
        batch.add(self.contract.functions.getContributions())
        batch.add(self.contract.functions.status())
        batch.add(self.contract.functions.manualFinalize())
