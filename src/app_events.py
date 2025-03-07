#!/usr/bin/env python3
import csv

from src import config
from src.web3client.event_ws import init_ws_event_scanner, EventScannerConfig, VestingContractDetails

vesting_contract_details = []
if config.backend.vesting_contract_details_csv is not None:
    data = list(csv.reader(open(config.backend.vesting_contract_details_csv)))
    header = data[0]
    assert header == ["beneficiary", "vestingAddress", "amount", "start", "end", "transferableBeneficiary", "revoker"]
    vesting_contract_details = []
    for row in data[1:]:
        row.extend([config.backend.addr_token, config.backend.addr_sn_rewards, config.backend.addr_sn_contrib_factory])
        vesting_contract_details.append(VestingContractDetails(*row))

config = EventScannerConfig(
    log_level=config.backend.log_level,
    enable_perf=config.backend.performance_logging,
    log_level_generic=config.backend.log_level_generic,
    genesis_block=config.backend.genesis_block,
    ws_max_run_depth=config.backend.ws_max_run_depth,
    ws_providers=config.backend.ws_providers,
    ws_max_size=config.backend.ws_max_size,
    addr_token=config.backend.addr_token,
    addr_sn_contrib_factory=config.backend.addr_sn_contrib_factory,
    addr_sn_rewards=config.backend.addr_sn_rewards,
    addr_reward_rate_pool=config.backend.addr_reward_rate_pool,
    sqlite_db=config.backend.sqlite_db,
    sqlite_schema=config.backend.sqlite_schema,
    db_reset_events_on_startup=config.backend.db_reset_events_on_startup,
    db_reset_contrib_on_startup=config.backend.db_reset_contrib_on_startup,
    reset_vesting_contracts_on_startup=config.backend.reset_vesting_contracts_on_startup,
    vesting_contract_details=vesting_contract_details,
    ws_watch_token_events=config.backend.ws_watch_token_events,
)

if __name__ == "__main__":
    init_ws_event_scanner(config)
