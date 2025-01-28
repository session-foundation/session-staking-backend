import logging

import eth_utils
from web3 import Web3, HTTPProvider
from web3.contract.contract import ContractFunction
from ..web3client.abi_manager import ABIManager


class Web3Client:
    def __init__(
        self,
        provider_urls: list[str],
        caller_address: str | None,
        private_key: str | None,
        logger: logging,
        abi_manager: ABIManager = ABIManager(),
    ):
        """
        Initialize the web3 client.

        :param provider_urls: List of URLs for Ethereum nodes to connect to.
        :param caller_address: Address of the caller.
        :param private_key: Private key of the caller.
        """
        self.web3 = Web3(HTTPProvider(endpoint_uri=provider_urls[0]))
        self.provider_url = provider_urls[0]
        self.abi_manager = abi_manager
        self.chain_id = self.web3.eth.chain_id

        self.private_key = private_key
        if private_key is None:
            logger.warning("private_key is None, contract writes will be disabled")

        if caller_address is not None:
            if not eth_utils.is_checksum_address(caller_address):
                raise ValueError("Caller address is not a checksum address")
            check_address = self.web3.eth.account.from_key(private_key).address
            if check_address != caller_address:
                raise ValueError("Private key address does not match the caller address")
            self.caller = eth_utils.to_checksum_address(caller_address)
        else:
            logger.warning("caller_address is None, contract writes will be disabled")
            self.caller = None

    def get_nonce(self):
        return self.web3.eth.get_transaction_count(self.caller)

    def contract_write(self, contract_function: ContractFunction, args: tuple):
        if self.caller is None:
            logging.warning("No contract caller, write is disabled")
            return None
        try:
            # Call your function
            address_to, amount = args
            call_function = contract_function(address_to, amount).build_transaction(
                {"chainId": self.chain_id, "from": self.caller, "nonce": self.get_nonce()}
            )

            # Sign transaction
            signed_tx = self.web3.eth.account.sign_transaction(
                call_function, private_key=self.private_key
            )

            # Send transaction
            send_tx = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # Wait for transaction receipt
            tx_hash = self.web3.eth.wait_for_transaction_receipt(send_tx).get("transactionHash")

            return tx_hash.hex()
        except Exception as e:
            logging.error("Error: {}".format(e))
            return None
