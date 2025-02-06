# Default configuration options for the session token staking website backend.
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
    """
    SHARED CONFIG
    """
    log_level                           = logging.INFO
    log_level_generic                   = None  # Logs from other packages will use log_level if this is not set
    oxen_wallet_regex:              str = ""
    sqlite_db:                      str = "ssb.db"
    sqlite_schema:                  str = "src/staking/schema.sql"
    rpc_shared:               list[str] = ""
    rpc_shared_cache:               int = 2
    disable_db_file_rewrite:       bool = False


    """
    API CONFIG
    """
    api_name:                       str = "api"
    rpc_api:                        str = ""
    rpc_api_cache:                  int = 2
    rpc_api_usage_logging:         bool = False
    rpc_api_usage_logging_interval: int = 300

    """
    REGISTRATION CONFIG
    """
    registration_api_name:              str = "registration_api"
    # NOTE: This can be the same DB as the main API, but you must manually run the registrations/schema.sql script in
    #   the main db so it can be populated with the required tables.
    registration_sqlite_db:             str = "ssb-registrations.db"
    registration_sqlite_schema:         str = "src/registration/schema.sql"
    # Creates a request per period limit by IP address (default is 100 requests per hour)
    registration_api_rate_limit:        int = 100
    registration_api_rate_limit_period: int = 3600

    """
    FETCHER CONFIG
    """
    abi_dir = "src/web3client/abis"
    # Arbitrum runs at ~4 blocks per second, and the rpc node has a limit of 30m, so scan for 120 blocks
    arbitrum_rescan_safety_blocks: int = 60
    arbitrum_scan_start_chunk_size: int = 20
    addr_reward_rate_pool:         str = "0x0000000000000000000000000000000000000000"
    addr_token:                    str = "0x0000000000000000000000000000000000000000"
    addr_sn_contrib:               str = "0x0000000000000000000000000000000000000000"
    addr_sn_contrib_factory:       str = "0x0000000000000000000000000000000000000000"
    addr_sn_rewards:               str = "0x0000000000000000000000000000000000000000"
    refresh_rate_seconds_arbitrum: int = 30
    max_time_keeper_events:        int = 10_000
    fetcher_name:                  str = "fetcher"
    performance_logging:          bool = False
    rpc_fetcher:                   str = ""
    rpc_fetcher_cache:             int = 2
    rpc_fetcher_usage_logging:    bool = False
    stale_time_seconds:            int = 30
    stale_time_seconds_contract_abis: int = 300
    thread_pool_max_workers:       int = 50
    web3_caller_address:    str | None = None
    web3_private_key:       str | None = None
    web3_provider_urls:      list[str] = ["http://localhost:8545"]  # Default hardhat private chain node address)

    """
    SNAPSHOT CONFIG
    """
    snapshot_task_name:                    str = "snapshot"
    sqlite_db_snapshot:                    str = "static/backend-snapshot.db"
    sqlite_snapshot_time_interval_seconds: int = 600
    snapshot_on_startup:                  bool = False

    """
    PRICE FETCHER CONFIG
    """
    prices_api_name:                    str = "prices_api"
    enable_price_fetcher:               bool = False
    coingecko_api_key:                  str = ""
    coingecko_api_url:                  str = "https://api.coingecko.com/api"
    coingecko_api_token_ids:      list[str] = ["ethereum", "chainflip"]
    coingecko_api_currencies:     list[str] = ["usd", "aud"]

    # Creates a request per period limit by IP address (default is 10 requests per 10 minutes)
    prices_api_rate_limit:              int = 10
    prices_api_rate_limit_period:       int = 600
    prices_sqlite_db:                   str = "ssb-prices.db"
    prices_sqlite_schema:               str = "price/schema.sql"
    prices_api_default_currency:        str = "usd"
    prices_api_default_token:           str = "ethereum"
    prices_api_refetch_interval_seconds:int = 300

# Session mainnet contracts
mainnet_backend = Backend()
mainnet_backend.oxen_wallet_regex      = f'L[{B58_ALPHABET}]{{94}}"'
mainnet_backend.rpc_shared             = "ipc://oxend/mainnet.sock"
mainnet_backend.sqlite_db              = "ssb-mainnet.db"

# Session testnet contracts
testnet_backend = Backend()
testnet_backend.oxen_wallet_regex       = f"T[{B58_ALPHABET}]{{96}}"
testnet_backend.rpc_shared              = "ipc://oxend/testnet.sock"
testnet_backend.sqlite_db               = "ssb-testnet.db"

# Session devnet.v3 contracts
devnet_backend = Backend()
devnet_backend.addr_reward_rate_pool    = "0xb515C61DE12f28eE908a905b930aFb80B9bAd7cf"
devnet_backend.addr_sn_contrib          = "0x0000000000000000000000000000000000000000"
devnet_backend.addr_sn_contrib_factory  = "0x0000000000000000000000000000000000000000"
devnet_backend.addr_sn_rewards          = "0x75Dc11700b2D03902FCb5Ca7aFd6A859a1Fa25Cb"
devnet_backend.oxen_wallet_regex        = f"dV[{B58_ALPHABET}]{{95}}"
devnet_backend.rpc_shared               = "ipc://oxend/devnet.sock"
devnet_backend.sqlite_db                = "ssb-devnet.db"
devnet_backend.web3_provider_urls        = ["https://sepolia-rollup.arbitrum.io/rpc"]

# Session stagenet.v3 contracts
stagenet_backend = Backend()
stagenet_backend.web3_provider_urls     = ["http://10.24.0.2/arb_sepolia"]
stagenet_backend.addr_reward_rate_pool   = "0xaAD853fE7091728dac0DAa7b69990ee68abFC636"
stagenet_backend.addr_token              = "0x7D7fD4E91834A96cD9Fb2369E7f4EB72383bbdEd"
stagenet_backend.addr_sn_contrib_factory = "0x36Ee2Da54a7E727cC996A441826BBEdda6336B71"
stagenet_backend.addr_sn_rewards         = "0x9d8aB00880CBBdc2Dcd29C179779469A82E7be35"
stagenet_backend.oxen_wallet_regex       = f"ST[{B58_ALPHABET}]{{95}}"
stagenet_backend.rpc_shared              = "tcp://localhost:6786"
stagenet_backend.sqlite_db               = "ssb-stagenet.db"

# Assign the active backend to be used in the sent-staking-backend
backend = stagenet_backend
