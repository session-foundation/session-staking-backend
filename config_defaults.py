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

# SQLite database used for persistent data, such as shorted registration URL tokens.
sqlite_db    = 'sent-backend.db'

mainnet_rpc  = 'ipc://oxend/mainnet.sock'
mainnet      = False

testnet_rpc  = 'ipc://oxend/testnet.sock'
testnet      = False

devnet_rpc   = 'ipc://oxend/devnet.sock'
devnet       = False

stagenet_rpc = 'ipc://oxend/stagenet.sock'
stagenet     = False

REWARD_RATE_POOL_ADDRESS                  = None
SERVICE_NODE_CONTRIBUTION_FACTORY_ADDRESS = None
SERVICE_NODE_REWARDS_ADDRESS              = None
SENT_TOKEN_ADDRESS                        = None
PROVIDER_ENDPOINT                         = None
