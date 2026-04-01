from web3 import Web3
from ..client import Web3Client


class ContractInterface:
    def __init__(
        self,
        web3_client: Web3Client,
        contract_address: str,
        contract_abi_name: str,
    ):
        """
        Initialize the connection to a contract.

        :param web3_client: The web3 client to use for interacting with the contract.
        :param contract_address: Address of the deployed contract.
        :param contract_abi_name: Path to the ABI file for the contract.
        """
        # Initialize address nonce

        self.web3_client = web3_client
        self.contract_address = Web3.to_checksum_address(contract_address)
        abi = self.web3_client.abi_manager.get_abi(contract_abi_name)
        # TODO: This call takes a while (~5ms) so we should see if we can cache it and reuse it for other instances with the same abi but different addresses
        self.contract = web3_client.web3.eth.contract(address=self.contract_address, abi=abi)
        self.address_map = {}
