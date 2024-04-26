#!/usr/bin/env python3

import random
import sys
import re
from nacl.signing import SigningKey

def usage(err = None):
    err = err + '\n\n' if err else ''
    print(f"""{err}
Usage: {sys.argv[0]} SEED WALLETADDR [CONTRACTADDR] URL

Create a (fake) SN registration signature, operated by WALLETADDR, and print out the URL to submit
it to a staking backend.

SEED is a number; the same seed will produce the same SN pubkey and BLS signatures.

WALLETADDR is the ETH operator address.  It can be the literal string "RANDOM" to make a random
fake address.

CONTRACTADDR is an ETH address of the multi-contributor contract for the SN.  If provided, this will
generate multi-contributor details; if omitted it will generate solo contributor info.  Can be given
as the literal string "RANDOM" to just make one up.

URL is the base API URL (e.g. http://127.0.0.1:5000/ or https://example.com/api) for the printed
URL.

""")
    sys.exit(1)

if not 4 <= len(sys.argv) <= 5:
    usage()

seed = sys.argv[1]
if not re.fullmatch(r'\d+', seed):
    usage(f"Invalid SEED")

re_eth = r'0x[a-fA-F0-9]{40}'
op = sys.argv[2]
if re.fullmatch(re_eth, op):
    op = bytes.fromhex(op[2:])
elif op == 'RANDOM':
    op = b'RANDOM'
else:
    usage(f"That doesn't look like an ETH wallet address")

contract = None
url_i = 4
if re.fullmatch(re_eth, sys.argv[3]):
    contract = bytes.fromhex(sys.argv[3][2:])
elif sys.argv[3] == 'RANDOM':
    contract = b'RANDOM'
else:
    url_i = 3

if url_i >= len(sys.argv):
    usage("missing URL")
url = sys.argv[url_i]
if not re.fullmatch(r'https?://.*', url):
    usage("That doesn't look like a URL")

if not url.endswith('/'):
    url = url + '/'

# Generate random keys, yay!
random.seed(seed)
pk_seed = random.randbytes(32)
pk_bls = random.randbytes(64)
pk_sig = random.randbytes(128)
sig_bls = random.randbytes(128)

if op == b'RANDOM':
    op = random.randbytes(20)
if contract == b'RANDOM':
    contract = random.randbytes(20)

a = SigningKey(pk_seed)
pk_ed = a.verify_key.encode()

to_sign = pk_ed + pk_bls + (contract if contract else op)
sig_ed = a.sign(to_sign)[0:64]

and_contract = f"&contract=0x{contract.hex()}" if contract else ""

print(f"{url}store/{pk_ed.hex()}?pubkey_bls={pk_bls.hex()}&sig_ed25519={sig_ed.hex()}&sig_bls={sig_bls.hex()}&operator=0x{op.hex()}{and_contract}")
