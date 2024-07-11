from web3 import Web3
from abi_manager import ABIManager

class RewardRatePoolInterface:
    def __init__(self, provider_url, contract_address):
        """
        Initialize the connection to the Ethereum provider and set up the contract.
        :param provider_url: URL of the Ethereum node to connect to.
        :param contract_address: Address of the RewardRatePool smart contract.
        """
        self.web3 = Web3(Web3.HTTPProvider(provider_url))
        manager = ABIManager()
        abi = manager.load_abi('RewardRatePool')
        self.contract = self.web3.eth.contract(address=Web3.to_checksum_address(contract_address), abi=abi)

    def calculate_total_deposited(self):
        """
        Calculates the total amount of SENT tokens deposited in the contract.
        """
        return self.contract.functions.calculateTotalDeposited().call()

    def calculate_released_amount(self, timestamp):
        """
        Calculates the amount of SENT tokens released up to a specific timestamp.
        :param timestamp: The timestamp until which to calculate the released amount.
        """
        return self.contract.functions.calculateReleasedAmount(timestamp).call()

    def calculate_interest_amount(self, balance, time_elapsed):
        """
        Calculates 14.5% annual interest for a given balance and time period.
        :param balance: The principal balance.
        :param time_elapsed: The time period in seconds.
        """
        return self.contract.functions.calculateInterestAmount(balance, time_elapsed).call()

    def reward_rate(self, timestamp):
        """
        Calculates the reward rate for a given timestamp.
        :param timestamp: The timestamp for which to calculate the reward rate.
        """
        return self.contract.functions.rewardRate(timestamp).call()

# Example usage:
# provider_url = 'http://127.0.0.1:8545'
# contract_address = '0x...'

# reward_rate_pool = RewardRatePoolInterface(provider_url, contract_address)
# total_deposited = reward_rate_pool.calculate_total_deposited()
# print("Total Deposited:", total_deposited)
# reward_rate = reward_rate_pool.reward_rate(Web3.toInt(text="latest"))
# print("Reward Rate at Latest:", reward_rate)

