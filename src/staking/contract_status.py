from typing import Iterable

# ServiceNodeContribution.Status: WaitForOperatorContrib, OpenForPublicContrib, WaitForFinalized, Finalized
CONTRACT_STATUSES = frozenset(range(4))


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
