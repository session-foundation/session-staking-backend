from config_defaults import *

# Local settings.  Changes to this file are meant for a local installation (and should not be
# committed to git).

# Example config overrides:
#sqlite_db = 'sent-database.db'
#mainnet_rpc = 'tcp://127.0.0.1:6789'
#testnet_rpc = 'tcp://127.0.0.1:6788'
#devnet_rpc = 'tcp://127.0.0.1:6787'

stagenet  = True
sqlite_db = 'stagenet.db'

REWARD_RATE_POOL_ADDRESS                  = '0x84a648F74Eaf037dD9558987F6179E692d5F2566'
SERVICE_NODE_CONTRIBUTION_FACTORY_ADDRESS = '0xff8C9cd4f9222d1FFB810EfcE63E048D72c5d61F'
SERVICE_NODE_REWARDS_ADDRESS              = '0xb691e7C159369475D0a3d4694639ae0144c7bAB2'
SENT_TOKEN_ADDRESS                        = '0x70c1f36C9cEBCa51B9344121D284D85BE36CD6bB'
PROVIDER_ENDPOINT                         = 'http://10.24.0.1:9547'
