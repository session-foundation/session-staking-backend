import logging

import config
from log import Log
from oxen.omq import omq_connection
from oxen.rpc import OxenRPC
from util import is_not_empty_string, valid_address_assertion


def validate_config(conf: config):
    log = Log("config_validate").logger
    log.perf.start("validate_config")
    log.info("Validating config")

    """
    Production warnings
    """
    if conf.backend.log_level < logging.INFO:
        log.warning(
            "Log level is set to {} which is less than INFO. This is not recommended for production.".format(
                conf.backend.log_level
            )
        )
    elif conf.backend.log_level > logging.ERROR:
        log.warning(
            "Log level is set to {} which is greater than ERROR. This is not recommended for production.".format(
                conf.backend.log_level
            )
        )

    if conf.backend.performance_logging:
        log.warning("Performance logging is enabled. This is not recommended for production.")

    """
    Validations
    """

    assert is_not_empty_string(conf.backend.sqlite_db), "sqlite_db is not set in config.py"
    rpc_url = conf.backend.rpc_fetcher if conf.backend.rpc_fetcher else conf.backend.rpc
    assert is_not_empty_string(rpc_url), "rpc url is not set in config.py requires rpc_fetcher or rpc"
    assert is_not_empty_string(
        conf.backend.oxen_wallet_regex
    ), "oxen_wallet_regex is not set in config.py"

    # Assert all contract addresses are valid
    valid_address_assertion(conf.backend.addr_sn_contrib, "addr_sn_contrib")
    valid_address_assertion(conf.backend.addr_sent, "addr_sent")
    valid_address_assertion(conf.backend.addr_sn_rewards, "addr_sn_rewards")
    valid_address_assertion(conf.backend.addr_reward_rate_pool, "addr_reward_rate_pool")

    assert is_not_empty_string(
        conf.backend.web3_provider_url
    ), "web3_provider_url is not set in config.py"

    """
    Web3 client validations
    """
    # web3_client = Web3Client(
    #     conf.backend.web3_provider_url,
    #     conf.backend.web3_caller_address,
    #     conf.backend.web3_private_key,
    #     log,
    # )
    # block_number = web3_client.web3.eth.block_number
    # log.debug("Config validation block number: {}".format(block_number))
    # assert block_number is not None, "Failed to get block number from web3 provider"

    """
    Oxen RPC validations
    """
    rpc = OxenRPC(log, rpc_url, 0)
    res = rpc.get_info().get()
    log.debug("Config validation rpc response status: {}".format(res.get("status")))
    assert (
        res is not None and res.get("status") == "OK"
    ), "Oxen RPC ping to {} failed with response: {}".format(conf.backend.rpc_fetcher, res)

    log.info("Config validation finished")
    log.perf.end("validate_config")
