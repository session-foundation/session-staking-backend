from web3client.client import Web3Client
from web3client.contracts.contract import ContractInterface


class TokenInterface(ContractInterface):
    abi_name = "Token"

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
