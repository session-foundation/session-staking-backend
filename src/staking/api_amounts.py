import dataclasses

# The response fields that hold token amounts. Amounts past 2^53 atomic units (about 9 million SESH)
# don't fit a JSON number exactly, so the API sends every amount as a decimal string.
AMOUNT_KEYS = frozenset({
    "amount",
    "reserved",
    "initial_amount",
    "staking_requirement",
    "total_contributed",
    "min_operator_contribution",
    "total_staked",
    "lifetime_liquidated_stakes",
    "lifetime_locked_stakes",
    "lifetime_rewards",
    "lifetime_unlocked_stakes",
    "locked_stakes",
    "timelocked_stakes",
    "claimed_stakes",
    "claimed_rewards",
    "balance_reward_rate_pool",
    "balance_service_node_rewards",
    "staking_reward_pool",
    # Contract event arguments.
    "stakedAmount",
    "returnedAmount",
    "newRequirement",
    "newThreshold",
    "previousBalance",
    "refund",
})


def amounts_as_text(value):
    """`value` with every int under an amount key as a decimal string, through dicts, lists and
    dataclasses (which become dicts, as the JSON encoder makes them)."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        value = {field.name: getattr(value, field.name) for field in dataclasses.fields(value)}
    if isinstance(value, dict):
        return {
            key: str(item) if key in AMOUNT_KEYS and isinstance(item, int) and not isinstance(item, bool)
            else amounts_as_text(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [amounts_as_text(item) for item in value]
    return value
