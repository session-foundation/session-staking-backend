# Default configuration options for SENT staking website backend.
#
# To override settings add `config.whatever = ...` into `config.py`; this file should not be
# modified and simply contains the default values.
#
# To override things that are specific to mainnet/testnet/etc. add `config.whatever = ...` lines
# into `mainnet.py`/`testnet.py`/etc.
import logging

# LMQ RPC endpoint of oxend; can be a unix socket 'ipc:///path/to/oxend.sock' or a tcp socket
# 'tcp://127.0.0.1:5678'.  mainnet_rpc/testnet_rpc/devnet_rpc are selected based on whether the
# backend is running through the mainnet.py, testnet.py, or devnet.py application script.

# SQLite database used for persistent data, such as shorted registration URL tokens.

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

class Backend:
    sqlite_db:               str = 'sent-backend.db'
    rpc:                     str = ''
    oxen_wallet_regex:       str = ''
    reward_rate_pool_addr:   str = '0x0000000000000000000000000000000000000000'
    sn_contrib_factory_addr: str = '0x0000000000000000000000000000000000000000'
    sn_rewards_addr:         str = '0x0000000000000000000000000000000000000000'
    sn_token_addr:           str = '0x0000000000000000000000000000000000000000'
    provider_url:            str = 'http://localhost:8545' # Default hardhat private chain node address
    log_level                    = logging.INFO

# Session mainnet contracts
mainnet_backend                          = Backend()
mainnet_backend.sqlite_db                = 'ssb-mainnet.db'
mainnet_backend.rpc                      = 'ipc://oxend/mainnet.sock'
mainnet_backend.oxen_wallet_regex        = f'L[{B58_ALPHABET}]{{94}}"'

# Session testnet contracts
testnet_backend                          = Backend()
testnet_backend.sqlite_db                = 'ssb-testnet.db'
testnet_backend.rpc                      = 'ipc://oxend/testnet.sock'
testnet_backend.oxen_wallet_regex        = f"T[{B58_ALPHABET}]{{96}}"

# Session devnet.v3 contracts
devnet_backend                           = Backend()
devnet_backend.sqlite_db                 = 'ssb-devnet.db'
devnet_backend.rpc                       = 'ipc://oxend/devnet.sock'
devnet_backend.oxen_wallet_regex         = f"dV[{B58_ALPHABET}]{{95}}"
devnet_backend.reward_rate_pool_addr     = '0xb515C61DE12f28eE908a905b930aFb80B9bAd7cf'
devnet_backend.sn_contrib_factory_addr   = '0x0000000000000000000000000000000000000000'
devnet_backend.sn_rewards_addr           = '0x75Dc11700b2D03902FCb5Ca7aFd6A859a1Fa25Cb'
devnet_backend.sn_token_addr             = '0x0000000000000000000000000000000000000000'
devnet_backend.provider_url              = 'https://sepolia-rollup.arbitrum.io/rpc'

# Session stagenet.v3 contracts
stagenet_backend                         = Backend()
stagenet_backend.sqlite_db               = 'ssb-stagenet.db'
stagenet_backend.rpc                     = 'ipc://oxend/stagenet.sock'
stagenet_backend.oxen_wallet_regex       = f"ST[{B58_ALPHABET}]{{95}}"
stagenet_backend.reward_rate_pool_addr   = '0x38cD8D3F93d591C18cf26B3Be4CB2c872aC37953'
stagenet_backend.sn_contrib_factory_addr = '0xF1bc0f928970C4ce891970F23c701238dC8417dD'
stagenet_backend.sn_rewards_addr         = '0x4abfFB7f922767f22c7aa6524823d93FDDaB54b1'
stagenet_backend.sn_token_addr           = '0x70c1f36C9cEBCa51B9344121D284D85BE36CD6bB'
stagenet_backend.provider_url            = 'https://sepolia-rollup.arbitrum.io/rpc'

# Assign the active backend to be used in the sent-staking-backend
backend                                  = stagenet_backend
