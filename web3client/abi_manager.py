import json
import os
from dataclasses import dataclass


@dataclass
class ABIData:
    name: str
    abi: dict
    bytecode: bytes
    deployed_bytecode: bytes


class ABIManager:

    cache = {}

    def __init__(self, db_writer=None, abi_dir="web3client/abis"):
        """
        Initializes the ABIManager with the directory containing ABI JSON files.

        :param db_writer: The db writer to use for interacting with the db.
        :param abi_dir: The directory where ABI files are stored. Default is 'abis'.
        """
        self.abi_dir = abi_dir
        if db_writer is not None:
            abis = self.load_all_abis()
            db_writer.write_smart_contract_abis_to_db(abis)

    def get_abi(self, contract_name):
        """
        Gets the ABI for a contract.
        """
        if contract_name in self.cache:
            return self.cache[contract_name]

        return self.load_abi(contract_name)

    def load_abi(self, file_name):
        """
        Loads the ABI from a specified artifact JSON file.

        :param file_name: The name of the artifact file (without .json extension).
        :return: The ABI extracted from the specified artifact JSON file.
        :raises FileNotFoundError: If the specified file does not exist.
        :raises KeyError: If the 'abi' key is not found in the JSON data.
        """
        if file_name in self.cache:
            return self.cache[file_name]

        file_path = os.path.join(self.abi_dir, "{}.json".format(file_name))
        if not os.path.exists(file_path):
            raise FileNotFoundError("No such file: {}".format(file_path))

        with open(file_path, "r") as file:
            data = json.load(file)
            if "abi" not in data:
                raise KeyError("Missing 'abi' key in the JSON file.")
            abi = data["abi"]
            name = data["contractName"]
            bytecode_bytes = data["bytecode"]
            deployed_bytecode_bytes = data["deployedBytecode"]
            self.cache[file_name] = abi
            return ABIData(name, abi, bytecode_bytes, deployed_bytecode_bytes)

    def load_all_abis(self):
        """
        Loads all ABIs from the specified directory.

        :return: A dictionary where the keys are the artifact names and the values are the ABIs.
        """
        abis = []
        for file in os.listdir(self.abi_dir):
            if file.endswith(".json"):
                name = file[:-5]
                abis.append(self.load_abi(name))
        return abis


# Example usage:
# manager = ABIManager()
# abi = manager.load_abi('MyContract')
# This `abi` can now be used with Web3 library to interact with a smart contract.
