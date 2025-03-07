import logging

from eth_utils import is_checksum_address

from .log import Log
from .oxen.rpc import OxenRPC
from .util import is_not_empty_string
from .web3client.client import Web3Client

log = Log("config_validate").logger

def validate_log_config(conf):
    if conf.log_level < logging.INFO:
        log.warning(
            "Log level is set to {} which is less than INFO. This is not recommended for production.".format(
                conf.log_level
            )
        )
    elif conf.log_level > logging.ERROR:
        log.warning(
            "Log level is set to {} which is greater than ERROR. This is not recommended for production.".format(
                conf.log_level
            )
        )

def validate_contract_addresses(conf):
    assert is_checksum_address(conf.addr_token), "addr_token is not a valid checksum address"
    assert is_checksum_address(conf.addr_sn_contrib_factory), "addr_sn_contrib_factory is not a valid checksum address"
    assert is_checksum_address(conf.addr_sn_rewards), "addr_sn_rewards is not a valid checksum address"
    assert is_checksum_address(conf.addr_reward_rate_pool), "addr_reward_rate_pool is not a valid checksum address"

def validate_web3_client(conf):
    assert conf.web3_provider_urls is not None and len(
        conf.web3_provider_urls
    ) > 0, "web3_provider_urls is not set in config.py"

    for web3_provider_url in conf.web3_provider_urls:
        assert is_not_empty_string(web3_provider_url), "web3_provider_urls is not set properly in config.py"

    web3_client = Web3Client(
        conf.web3_provider_urls,
        conf.web3_caller_address,
        conf.web3_private_key,
        log,
    )

    block_number = web3_client.web3.eth.block_number
    log.debug("Config validation block number: {}".format(block_number))
    assert block_number is not None, "Failed to get block number from web3 provider"

def validate_oxen_rpc(conf):
    rpc = OxenRPC(log, conf.rpc_shared, 0)
    res = rpc.get_info().get()
    log.debug("Config validation rpc response status: {}".format(res.get("status")))
    assert (
        res is not None and res.get("status") == "OK"
    ), "Oxen RPC ping to {} failed with response: {}".format(conf.rpc_shared, res)
