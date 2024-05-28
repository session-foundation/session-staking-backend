# Default configuration options for SENT staking website backend.
#
# To override settings add `config.whatever = ...` into `config.py`; this file should not be
# modified and simply contains the default values.
#
# To override things that are specific to mainnet/testnet/etc. add `config.whatever = ...` lines
# into `mainnet.py`/`testnet.py`/etc.


# LMQ RPC endpoint of oxend; can be a unix socket 'ipc:///path/to/oxend.sock' or a tcp socket
# 'tcp://127.0.0.1:5678'.  mainnet_rpc/testnet_rpc/devnet_rpc are selected based on whether the
# backend is running through the mainnet.py, testnet.py, or devnet.py application script.
mainnet_rpc = 'ipc://oxend/mainnet.sock'
testnet_rpc = 'ipc://oxend/testnet.sock'
devnet_rpc = 'ipc://oxend/devnet.sock'

# SQLite database used for persistent data, such as shorted registration URL tokens.
sqlite_db = 'sent-backend.db'

testnet = False
devnet = False

REWARD_RATE_POOL_ADDRESS = '0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0'
SERVICE_NODE_CONTRIBUTION_FACTORY_ADDRESS = '0x06b8F568F9ed3E2f0393892b374437D253b733E7'
SERVICE_NODE_REWARDS_ADDRESS = '0x5FC8d32690cc91D4c39d9d3abcBD16989F875707'
SENT_TOKEN_ADDRESS = '0x5FbDB2315678afecb367f032d93F642f64180aa3'

PROVIDER_ENDPOINT = 'https://sepolia-rollup.arbitrum.io/rpc'
