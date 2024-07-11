import json
import os

class ABIManager:
    def __init__(self, abi_dir='abis'):
        """
        Initializes the ABIManager with the directory containing ABI JSON files.

        :param abi_dir: The directory where ABI files are stored. Default is 'abis'.
        """
        self.abi_dir = abi_dir

    def load_abi(self, artifact_name):
        """
        Loads the ABI from a specified artifact JSON file.

        :param artifact_name: The name of the artifact file (without .json extension).
        :return: The ABI extracted from the specified artifact JSON file.
        :raises FileNotFoundError: If the specified file does not exist.
        :raises KeyError: If the 'abi' key is not found in the JSON data.
        """
        file_path = os.path.join(self.abi_dir, f"{artifact_name}.json")
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"No such file: {file_path}")

        with open(file_path, 'r') as file:
            data = json.load(file)
            if 'abi' not in data:
                raise KeyError("Missing 'abi' key in the JSON file.")
            return data['abi']

# Example usage:
# manager = ABIManager()
# abi = manager.load_abi('MyContract')
# This `abi` can now be used with Web3 library to interact with a smart contract.

