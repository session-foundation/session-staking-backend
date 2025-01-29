import nacl.hash
import nacl.bindings as sodium
from nacl.signing import VerifyKey


class SNSignatureValidationError(ValueError):
    pass


def check_reg_keys_sigs(params):
    if len(params["pubkey_ed25519"]) != 32 or not sodium.crypto_core_ed25519_is_valid_point(
        params["pubkey_ed25519"]
    ):
        raise SNSignatureValidationError("Ed25519 pubkey is invalid")
    if len(params["pubkey_bls"]) != 64:  # FIXME: bls pubkey validation?
        raise SNSignatureValidationError("BLS pubkey is invalid")
    if len(params["operator"]) != 20:
        raise SNSignatureValidationError("operator address is invalid")
    contract = params.get("contract")
    if contract is not None and len(contract) != 20:
        raise SNSignatureValidationError("contract address is invalid")

    signed = params["pubkey_ed25519"] + params["pubkey_bls"]

    try:
        VerifyKey(params["pubkey_ed25519"]).verify(signed, params["sig_ed25519"])
    except nacl.exceptions.BadSignatureError:
        raise SNSignatureValidationError("Ed25519 signature is invalid")

    # FIXME: BLS verification of pubkey_bls on signed
    if False:
        raise SNSignatureValidationError("BLS signature is invalid")
