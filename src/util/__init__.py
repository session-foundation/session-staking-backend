from eth_utils import is_address


def is_not_empty_string(value) -> bool:
    return value is not None and len(value) > 0

def format_seconds(seconds: int | float, precision: int = 3) -> str:
    assert precision >= 0
    if precision == 0:
        return seconds.__round__().__str__()
    return seconds.__round__(precision).__str__()


def format_ms(ms: int | float, precision: int = 3) -> str:
    assert precision >= 0
    if precision == 0:
        return ms.__round__().__str__()
    return ms.__round__(precision).__str__()
