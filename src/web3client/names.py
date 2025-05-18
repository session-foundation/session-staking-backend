from ens.auto import ns


def reverse_lookup_ens(name_service: ns, address: str) -> str:
    if not address.startswith("0x"):
        address = "0x" + address

    return name_service.name(address)
