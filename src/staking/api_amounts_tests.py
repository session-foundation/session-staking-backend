from dataclasses import dataclass

from .api_amounts import amounts_as_text
from .dataclasses import RewardsInfo

# Past 2^53, where a JSON number stops being exact.
LARGE = 22_795_422_631_493_348_102


@dataclass
class Contribution:
    address: str
    amount: int


def test_amounts_become_strings_and_nothing_else_does():
    vals = {
        "network": {"staking_requirement": 25_000 * 10**9, "block_height": 7, "hard_fork": 21},
        "nodes": [{"total_contributed": 25_000 * 10**9, "active": True, "contract_id": 3,
                   "contributors": [Contribution("0xaa", 5_000 * 10**9)],
                   "events": [{"name": "RewardsClaimed", "args": {"amount": LARGE, "serviceNodeID": 3}}]}],
        "rewards": RewardsInfo("0xaa", LARGE, 0, 1, LARGE, 2, 3, 4),
    }

    out = amounts_as_text(vals)

    assert out["network"] == {"staking_requirement": "25000000000000", "block_height": 7, "hard_fork": 21}
    node = out["nodes"][0]
    assert (node["total_contributed"], node["active"], node["contract_id"]) == ("25000000000000", True, 3)
    assert node["contributors"] == [{"address": "0xaa", "amount": "5000000000000"}]
    assert node["events"][0]["args"] == {"amount": str(LARGE), "serviceNodeID": 3}
    assert out["rewards"]["amount"] == str(LARGE)
    assert out["rewards"]["lifetime_rewards"] == str(LARGE)
    assert out["rewards"]["address"] == "0xaa"


def test_missing_amounts_stay_null():
    assert amounts_as_text({"amount": None, "reserved": 0}) == {"amount": None, "reserved": "0"}
