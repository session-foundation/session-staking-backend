from config_defaults import *

# Local settings.  Changes to this file are meant for a local installation (and should not be
# committed to git).

# Example config overrides:
#sqlite_db = 'sent-database.db'
#mainnet_rpc = 'tcp://127.0.0.1:6789'
#testnet_rpc = 'tcp://127.0.0.1:6788'
#devnet_rpc = 'tcp://127.0.0.1:6787'

stagenet = True

sqlite_db = 'stagenet.db'

REWARD_RATE_POOL_ADDRESS = '0x408bCc6C9b942ECc4F289C080d2A1a2a3617Aff8'
SERVICE_NODE_CONTRIBUTION_FACTORY_ADDRESS = '0x10DF3F7d65a660F5780b1b7A9451B752649E169D'
SERVICE_NODE_REWARDS_ADDRESS = '0xEF43cd64528eA89966E251d4FE17c660222D2c9d'
SENT_TOKEN_ADDRESS = '0x7FBDC29b81e410eB0eaE75Dca64a76d898EAc4A9'

PROVIDER_ENDPOINT = 'http://10.24.0.1:9547'
