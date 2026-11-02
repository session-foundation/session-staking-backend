import re
from typing import Iterable

# ServiceNodeContribution.Status: WaitForOperatorContrib, OpenForPublicContrib, WaitForFinalized, Finalized
CONTRACT_STATUSES = frozenset(range(4))

CONTRACT_ADDRESS_RE = re.compile("0x[0-9a-fA-F]{40}")


def parse_contract_statuses(values: Iterable[str]) -> set[int]:
    """
    Parses `status` query string values into contract statuses.  Raises ValueError if a value is not
    a known contract status.
    """
    statuses = {int(value) for value in values}
    unknown = statuses - CONTRACT_STATUSES
    if unknown:
        raise ValueError(f"Unknown contract status: {sorted(unknown)}")
    return statuses


def parse_contract_address(value: str | None) -> str | None:
    """
    Parses an `address` query string value into a lowercase contract address, or None when absent.
    Raises ValueError if the value is not an Ethereum address.
    """
    if value is None:
        return None
    if not CONTRACT_ADDRESS_RE.fullmatch(value):
        raise ValueError(f"Invalid contract address: {value}")
    return value.lower()
