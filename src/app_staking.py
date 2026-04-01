#!/usr/bin/env python3
from src import config
from src.staking.app import create_app, StakingAppConfig

staking_app_config = StakingAppConfig(
    name="staking_api",
    log_level=config.backend.log_level,
    enable_perf=config.backend.performance_logging,
    sqlite_db=config.backend.sqlite_db,
    sqlite_schema=config.backend.sqlite_schema,
    sqlite_db_registrations=config.backend.registration_sqlite_db,
    sqlite_schema_registrations=config.backend.registration_sqlite_schema,
    rpc_api_cache=config.backend.rpc_api_cache,
    rpc_shared=config.backend.rpc_shared,
    rpc_shared_cache=config.backend.rpc_shared_cache,
    rpc_api_usage_logging=config.backend.rpc_api_usage_logging,
    log_level_generic=config.backend.log_level_generic,
    cache_stale_time_seconds=config.backend.stale_time_seconds,
    disable_db_file_rewrite=config.backend.disable_db_file_rewrite,
    stale_time_seconds_contract_abis=config.backend.stale_time_seconds_contract_abis,
    stale_time_ens_name=config.backend.stale_time_ens_name,
    rpc_api_usage_logging_interval=config.backend.rpc_api_usage_logging_interval,
    web3_provider_urls_eth=config.backend.web3_provider_urls_eth,
)

app = create_app(staking_app_config)