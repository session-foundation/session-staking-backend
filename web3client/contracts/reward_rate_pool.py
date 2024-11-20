from web3client.client import Web3Client
from web3client.contracts.contract import ContractInterface


class RewardRatePoolInterface(ContractInterface):
    abi_name = "RewardRatePool"

    def __init__(self, web3_client: Web3Client, contract_address: str):
        super().__init__(web3_client, contract_address, RewardRatePoolInterface.abi_name)

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
