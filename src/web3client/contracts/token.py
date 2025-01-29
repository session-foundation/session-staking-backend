from ..client import Web3Client
from ..contracts.contract import ContractInterface


class TokenInterface(ContractInterface):
    abi_name = "Token"

    decimals = 9

    def __init__(self, web3_client: Web3Client, contract_address: str):
        super().__init__(web3_client, contract_address, TokenInterface.abi_name)

    def transfer(self, amount: int, address_to: str):
        """
        Calls the transfer function on the ERC20 token contract

        :return: receipt
        """
        return self.web3_client.contract_write(
            self.contract.functions.transfer, (address_to, amount)
        )

    def balance_of(self, address: str):
        """
        Calls the balanceOf function on the ERC20 token contract

        :return: balance
        """
        return self.contract.functions.balanceOf(address).call()

    @staticmethod
    def to_atomic(amount: float | int) -> int:
        """
        Converts a float or int to an atomic amount
        """
        print(TokenInterface.decimals)
        print(amount)
        print((amount * 10 ** TokenInterface.decimals))
        return int(amount * 10 ** TokenInterface.decimals)

    @staticmethod
    def from_atomic(amount: int) -> float:
        """
        Converts an atomic amount to a float
        """
        return amount / 10 ** TokenInterface.decimals
