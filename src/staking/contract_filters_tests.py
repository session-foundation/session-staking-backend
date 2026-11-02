import pytest

from .contract_filters import parse_contract_address, parse_contract_statuses


def test_parse_contract_statuses():
    assert parse_contract_statuses([]) == set()
    assert parse_contract_statuses(["1"]) == {1}
    assert parse_contract_statuses(["0", "1", "1"]) == {0, 1}


@pytest.mark.parametrize("value", ["4", "-1", "open", "", "1.0"])
def test_parse_contract_statuses_rejects_unknown(value):
    with pytest.raises(ValueError):
        parse_contract_statuses([value])


def test_parse_contract_address():
    assert parse_contract_address(None) is None
    assert (
        parse_contract_address("0xFc44111FF5C87F70B4d78A6DE4f51F6536f5A7e9")
        == "0xfc44111ff5c87f70b4d78a6de4f51f6536f5a7e9"
    )


@pytest.mark.parametrize(
    "value",
    ["", "0x", "Fc44111FF5C87F70B4d78A6DE4f51F6536f5A7e9", "0xFc44111FF5C87F70B4d78A6DE4f51F6536f5A7e", "0xZc44111FF5C87F70B4d78A6DE4f51F6536f5A7e9"],
)
def test_parse_contract_address_rejects_invalid(value):
    with pytest.raises(ValueError):
        parse_contract_address(value)
