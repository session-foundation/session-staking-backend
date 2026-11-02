import pytest

from .contract_status import parse_contract_statuses


def test_parse_contract_statuses():
    assert parse_contract_statuses([]) == set()
    assert parse_contract_statuses(["1"]) == {1}
    assert parse_contract_statuses(["0", "1", "1"]) == {0, 1}


@pytest.mark.parametrize("value", ["4", "-1", "open", "", "1.0"])
def test_parse_contract_statuses_rejects_unknown(value):
    with pytest.raises(ValueError):
        parse_contract_statuses([value])
