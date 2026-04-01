import re
from typing import Callable, Any, Union
from functools import partial

import string

import eth_utils
import flask
import oxenc
from eth_typing import ChecksumAddress
from werkzeug.routing import BaseConverter

eth_regex = "0x[0-9a-fA-F]{40}"

def parse_bls_pubkey(bls_pubkey: dict):
    x, y = bls_pubkey["X"], bls_pubkey["Y"]
    return f"{x:064x}{y:064x}"

def parse_ed25519_pubkey(ed25519_pubkey: int):
    return f"{ed25519_pubkey:064x}"

def raw_eth_addr(k, v):
    if re.fullmatch(eth_regex, v):
        if not eth_utils.is_address(v):
            raise ParseError(k, "ETH address checksum failed")
        return bytes.fromhex(v[2:])
    raise ParseError(k, "not an ETH address")

def get_relative_time_from_ms(ms: int, short: bool = False, include_suffix = False):
    if include_suffix:
        prefix, suffix = ("in ", "") if ms > 0 else ("", " ago")
    else:
        prefix, suffix = "", ""

    if ms < 1000:
        time = "{} {}".format(ms, ("ms" if short else "milliseconds"))
    elif ms < 1000 * 60:
        time = "{} {}".format(ms // 1000, ("s" if short else "seconds"))
    elif ms < 1000 * 60 * 60:
        time = "{} {}".format(ms // (1000 * 60), ("m" if short else "minutes"))
    elif ms < 1000 * 60 * 60 * 24:
        time = "{} {}".format(ms // (1000 * 60 * 60), ("h" if short else "hours"))
    else:
        time = "{} {}".format(ms // (1000 * 60 * 60 * 24), ("d" if short else "days"))

    return f"{prefix}{time}{suffix}"

def hexify(container):
    """
    Takes a dict or list and mutates it to change any `bytes` values in it to str hex representation
    of the bytes, recursively.
    """
    if isinstance(container, dict):
        it = container.items()
    elif isinstance(container, list):
        it = enumerate(container)
    else:
        return

    for i, v in it:
        if isinstance(v, bytes):
            container[i] = v.hex()
        else:
            hexify(v)

def eth_format(addr: Union[bytes, str]) -> ChecksumAddress:
    try:
        return eth_utils.to_checksum_address(addr)
    except ValueError:
        raise ParseError(addr, "Invalid ETH address")

class EthConverter(BaseConverter):
    def __init__(self, url_map):
        super().__init__(url_map)
        self.regex = eth_regex


# Validates that input is 64 hex bytes and converts it to 32 bytes.
class Hex64Converter(BaseConverter):
    def __init__(self, url_map):
        super().__init__(url_map)
        self.regex = "[0-9a-fA-F]{64}"

    def to_python(self, value):
        return bytes.fromhex(value)

    def to_url(self, value):
        return value.hex()


class ParseError(ValueError):
    def __init__(self, field, reason):
        self.field = field
        super().__init__(f"{field}: {reason}")


class ParseMissingError(ParseError):
    def __init__(self, field):
        super().__init__(field, f"required parameter is missing")


class ParseUnknownError(ParseError):
    def __init__(self, field):
        super().__init__(field, f"unknown parameter")


class ParseMultipleError(ParseError):
    def __init__(self, field):
        super().__init__(field, f"cannot be specified multiple times")


def parse_query_params(params: dict[str, Callable[[str, str], Any]]):
    """
    Takes a dict of fields and callables such as:

        {
            "field": ("out", callable),
            ...
        }

    where:
    - `"field"` is the expected query string name
    - `callable` will be invoked as `callable("field", value)` to determined the returned value.

    On error, throws a ParseError with `.field` set to the "field" name that triggered the error.

    Notes:
    - callable should throw a ParseError for an unaccept input value.
    - if "-field" starts with "-" then the field is optional; otherwise it is an error if not
      provided.  The "-" is not included in the returned key.
    - if "field" ends with "[]" then the value will be an array of values returned by the callable,
      and the parameter can be specified multiple times.  Otherwise a value can be specified only
      once.  The "[]" is not included in the returned key.
    - you can do both of the above: "-field[]" will allow the value to be provided zero or more
      times; the value will be omitted if not present in the input, and an array (under the "field")
      key if provided at least once.
    """

    parsed = {}

    param_map = {
        k.removeprefix("-").removesuffix("[]"): (
            k.startswith("-"),
            k.endswith("[]"),
            cb,
        )
        for k, cb in params.items()
    }

    for k, v in flask.request.values.items(multi=True):
        found = param_map.get(k)
        if found is None:
            raise ParseUnknownError(k)

        _, multi, callback = found

        if multi:
            parsed.setdefault(k, []).append(callback(k, v) if callback else v)
        elif k not in parsed:
            parsed[k] = callback(k, v) if callback else v
        else:
            raise ParseMultipleError(k)

    for k, p in param_map.items():
        optional = p[0]
        if not optional and k not in flask.request.values:
            raise ParseMissingError(k)

    return parsed


# Decodes `x` into a bytes of length `length`.  `x` should be hex or base64 encoded, without
# whitespace.  Both regular and "URL-safe" base64 are accepted.  Padding is optional for base64
# values.  Throws ParseError if the input is invalid or of the wrong size.  `length` must be at
# least 5 (smaller byte values are harder or even ambiguous to distinguish between hex and base64).
def decode_bytes(k, x, length):
    assert length >= 5

    hex_len = length * 2
    b64_unpadded = (length * 4 + 2) // 3
    b64_padded = (length + 2) // 3 * 4

    if len(x) == hex_len and all(c in string.hexdigits for c in x):
        return bytes.fromhex(x)
    if len(x) in (b64_unpadded, b64_padded):
        if oxenc.is_base64(x):
            return oxenc.from_base64(x)
        if "-" in x or "_" in x:  # Looks like (maybe) url-safe b64
            x = x.replace("/", "_").replace("+", "-")
        if oxenc.is_base64(x):
            return oxenc.from_base64(x)
    raise ParseError(k, f"expected {hex_len} hex or {b64_unpadded} base64 characters")


def byte_decoder(length: int):
    return partial(decode_bytes, length=length)
