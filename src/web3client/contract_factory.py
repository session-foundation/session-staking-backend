import subprocess
from solcx import compile_source, install_solc
import pathlib

SOLC_VERSION = "0.8.26"
install_solc(SOLC_VERSION)

base_path = pathlib.Path(__file__).parent.parent.parent.joinpath("session-token-contracts")

subprocess.run(["pnpm", "install"], cwd=base_path)

compiled_sol = compile_source(
    """
import "ServiceNodeRewards.sol";
import "RewardRatePool.sol";
import "SESH.sol";
import "ServiceNodeContribution.sol";
import "ServiceNodeContributionFactory.sol";
import "utils/TokenVestingStaking.sol";
import "utils/TokenVestingNoStaking.sol";
import "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts/interfaces/IERC1967.sol";
""",
    base_path=base_path,
    include_path=base_path.joinpath("contracts"),
    solc_version=SOLC_VERSION,
    import_remappings={
        "@openzeppelin/contracts": "node_modules/@openzeppelin/contracts",
        "@openzeppelin/contracts-upgradeable": "node_modules/@openzeppelin/contracts-upgradeable",
    },
)

abis = {}


class ContractFactory:
    def __init__(self, w3):
        """
        Creates factories for the contracts in the session-token-contracts repo.

        Factories can be used to instantiate contracts with the same ABI and bytecode by calling them with the address
        of the contract.

        Example:
            factory = ContractFactory(w3)
            sesh_contract = factory.SESH(address)
        """
        self.w3 = w3

    def get(self, name: str):
        if name not in abis:
            key = f"{name}.sol:{name}"

            if name == "Ownable2StepUpgradeable":
                key = "node_modules/@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol:Ownable2StepUpgradeable"
            elif name == "PausableUpgradeable":
                key = "node_modules/@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol:PausableUpgradeable"
            elif name == "IERC1967":
                key = "node_modules/@openzeppelin/contracts/interfaces/IERC1967.sol:IERC1967"
            elif name == "TokenVestingStaking":
                key = "utils/TokenVestingStaking.sol:TokenVestingStaking"
            elif name == "TokenVestingNoStaking":
                key = "utils/TokenVestingNoStaking.sol:TokenVestingNoStaking"

            abis[name] = self.w3.eth.contract(abi=compiled_sol[key]["abi"])
        return abis[name]

    @property
    def SESH(self):
        return self.get("SESH")

    @property
    def RewardRatePool(self):
        return self.get("RewardRatePool")

    @property
    def ServiceNodeRewards(self):
        return self.get("ServiceNodeRewards")

    @property
    def ServiceNodeContributionFactory(self):
        return self.get("ServiceNodeContributionFactory")

    @property
    def ServiceNodeContribution(self):
        return self.get("ServiceNodeContribution")

    @property
    def TokenVestingStaking(self):
        return self.get("TokenVestingStaking")

    @property
    def TokenVestingNoStaking(self):
        return self.get("TokenVestingNoStaking")

    @property
    def Ownable2StepUpgradeable(self):
        return self.get("Ownable2StepUpgradeable")

    @property
    def PausableUpgradeable(self):
        return self.get("PausableUpgradeable")
