from   web3        import Web3
from   abi_manager import ABIManager

class ServiceNodeRewardsRecipient:
    def __init__(self):
        self.rewards = 0
        self.claimed = 0

class ServiceNodeRewardsMapEntry:
    def __init__(self):
        self.value  = ServiceNodeRewardsRecipient()
        self.height = 0;

class ServiceNodeRewardsInterface:
    def __init__(self, provider_url: str, contract_address: str):
        """
        Initialize the connection to the ServiceNodeContributionFactory contract.

        :param provider_url: URL of the Ethereum node to connect to.
        :param contract_address: Address of the deployed ServiceNodeContributionFactory contract.
        """
        self.web3             = Web3(Web3.HTTPProvider(provider_url))
        self.contract_address = Web3.to_checksum_address(contract_address)
        manager               = ABIManager()
        abi                   = manager.load_abi('ServiceNodeRewards')
        self.contract         = self.web3.eth.contract(address=self.contract_address, abi=abi)
        self.address_map      = {}

    def allServiceNodeIDs(self):
        """
        Calls the allServiceNodeIds function to get the `id` and `bls_key` lists

        :return: The `id` and `bls_key` lists
        """
        return self.contract.functions.allServiceNodeIDs().call()

    def recipients(self, eth_address: bytes) -> ServiceNodeRewardsRecipient:
        """
        Calls the view function to get 'Recipient'

        :return: The recipient struct containing the 'rewards' and 'claimed' amount in the smart contract
        """

        # Validate the eth address
        result = ServiceNodeRewardsRecipient()
        if len(eth_address) != 20:
            return result

        # Create a recipient entry in our cache if it doesn't exist yet
        if eth_address not in self.address_map:
            self.address_map[eth_address] = ServiceNodeRewardsMapEntry()

        # Snap the current height
        height = self.web3.eth.block_number

        # Retrieve the recipient entry and check if enough time has elapsed to
        # update the entry, otherwise return the cached entry
        entry  = self.address_map[eth_address]
        result = entry.value
        if entry.height >= height:
            return result

        # NOTE: Assuming a block time of 0.25s, we want a 30s block buffer.
        # TODO: This value is copied from oxen-core of the same name
        # `SAFE_BLOCKS`
        SAFE_BLOCKS              = 30 / 0.25;
        blocks_since_last_update = height - entry.height
        if blocks_since_last_update < SAFE_BLOCKS:
            return result

        # Enough blocks has elapsed, query the rewards from the contract
        call_result    = self.contract.functions.recipients(eth_address).call(block_identifier=height)
        result.rewards = call_result[0]
        result.claimed = call_result[1]

        assert result.claimed <= result.rewards, "Contract returned that wallet '{}' claimed {} more than the rewards {} allocated to it!".format(eth_address.decode('utf-8'),
                                                                                                                                                  result.rewards,
                                                                                                                                                  result.claimed)


        # Assign the updated entry back into the cache
        entry.height                  = height
        entry.value                   = result
        self.address_map[eth_address] = entry

        return result
