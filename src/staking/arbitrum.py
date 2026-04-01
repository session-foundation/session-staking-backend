import logging
from dataclasses import dataclass

import eth_utils
from web3.exceptions import BlockNotFound

from ..web3client.client import Web3Client
from ..web3client.contracts.service_node_contribution import ServiceNodeContributionInterface
from ..web3client.contracts.service_node_contribution_factory import ServiceNodeContributionFactory
from ..web3client.contracts.service_node_rewards import ServiceNodeRewardsInterface
from ..web3client.event_scanner import ProcessedEvent


# TODO: we should be able to remove this once contract_id is always available via rpc.get_service_nodes
def get_service_node_rewards_contract_id_map(contract: ServiceNodeRewardsInterface):
    """
    Update the map of service node contract ids to BLS public keys. This fetches the list of all service nodes from the
    Service Node Rewards contract and maps them to their corresponding contract ids.
    """
    [ids, bls_keys] = contract.get_all_service_node_contract_ids()
    return {f"{x:064x}{y:064x}": contract_id for contract_id, (x, y) in zip(ids, bls_keys)}


def get_new_contribution_contracts(
    web3_client: Web3Client,
    logger: logging,
    interface: ServiceNodeContributionFactory,
    last_block: int,
    end_block: int,
):
    logger.perf.start("get_new_contribution_contracts")
    events = interface.event_scanner.run(last_block=last_block, end_block=end_block)

    logger.perf.start("create_contribution_contract_instances")
    contracts = [
        ServiceNodeContributionInterface(web3_client, event.args.contributorContract)
        for event in events
        if eth_utils.is_address(event.args.contributorContract)
    ]
    logger.perf.end("create_contribution_contract_instances")
    logger.debug("Found {} new contract events".format(len(events)))
    logger.debug("Found {} new contracts".format(len(contracts)))
    logger.perf.end("get_new_contribution_contracts")
    return contracts, events


@dataclass
class ContributionContractDetails:
    address: str | None
    fee: int | None
    manual_finalize: bool | None
    operator_address: str | None
    pubkey_bls: str | None
    service_node_pubkey: str | None
    service_node_signature: str | None
    status: int | None


def update_contribution_contract_details(
    web3_client: Web3Client,
    logger: logging,
    contracts: list[ServiceNodeContributionInterface],
    max_requests_per_batch=1000,
):
    logger.perf.start("chunk_contribution_contract_instances")
    assert len(contracts) > 0, "Expected at least one contract"
    assert max_requests_per_batch > 0, "Expected max_requests_per_batch > 0"

    requests_per_contract = (
        ServiceNodeContributionInterface.add_details_fetch_to_batch_added_batches()
    )

    max_chunk_size = max_requests_per_batch // requests_per_contract

    logger.debug(
        "contracts: {}, requests_per_contract: {}, max_chunk_size: {}".format(
            len(contracts), max_requests_per_batch, max_chunk_size
        )
    )

    chunks = [contracts[i : i + max_chunk_size] for i in range(0, len(contracts), max_chunk_size)]
    logger.perf.end("chunk_contribution_contract_instances")

    logger.perf.start("fetch_contribution_contract_details total")
    responses = []
    for chunk in chunks:

        assert len(chunk) <= max_requests_per_batch, "Expected chunk size <= {} got {}".format(
            max_requests_per_batch, len(chunk)
        )

        logger.perf.start("fetch_contribution_contract_details_chunk of size {}".format(len(chunk)))
        with web3_client.web3.batch_requests() as batch:
            for contract in chunk:
                contract.add_details_fetch_to_batch(batch)

            res = batch.execute()
            responses.extend(res)
        logger.perf.end("fetch_contribution_contract_details_chunk of size {}".format(len(chunk)))

    assert (
        len(responses) == len(contracts) * requests_per_contract
    ), "Expected {} responses, got {}".format(len(contracts), len(responses))

    contract_details = []
    contributions_list = []

    for i in range(0, len(responses), requests_per_contract):
        contract_address = contracts[i // requests_per_contract].contract_address

        params = responses[i]

        operator_address = responses[i + 1]
        pubkey_bls_data = responses[i + 2]

        contributions = responses[i + 3]
        contributions_addresses = contributions[0]
        contributions_beneficiaries = contributions[1]
        contributions_amounts = contributions[2]

        reserved = responses[i + 6]
        reserved_addresses = reserved[0]
        reserved_amounts = reserved[1]

        contributor_slots = {}

        for j in range(len(contributions_addresses)):
            address = contributions_addresses[j]
            contributor_slots[address] = {
                "contract_address": contract_address,
                "address": address,
                "amount": contributions_amounts[j],
                "beneficiary_address": contributions_beneficiaries[j],
                "reserved": 0,
            }

        for j in range(len(reserved_addresses)):
            address = reserved_addresses[j]
            amount = reserved_amounts[j]
            contributor_slots.setdefault(address, {"contract_address": contract_address, "address": address, "beneficiary_address":address, "amount": 0}).update({"reserved": amount})

        status = responses[i + 4]

        manual_finalize = responses[i + 5]

        contributions_list.extend(contributor_slots.values())

        contract_details.append(
            ContributionContractDetails(
                address=contract_address,
                fee=params[3],
                manual_finalize=manual_finalize,
                operator_address=operator_address,
                pubkey_bls="0x{:0128x}".format((pubkey_bls_data[0] << 256) + pubkey_bls_data[1]),
                service_node_pubkey=f"{params[0]:032x}",
                service_node_signature=f"{params[1]:032x}{params[2]:032x}",
                status=status,
            )
        )

    logger.debug("Fetched details for {} contracts".format(len(contract_details)))

    logger.perf.end("fetch_contribution_contract_details total")
    return contract_details, contributions_list


def get_block_timestamp(web3_client: Web3Client, block_num: int):
    """Get block timestamp"""
    try:
        block_info = web3_client.web3.eth.get_block(block_num)
    except BlockNotFound:
        # Block was not mined yet,
        # minor chain reorganisation?
        return None
    return block_info.get("timestamp")


def estimate_block_timestamp(ref_block: int, ref_block_timestamp: int, target_block: int):
    """Estimate block timestamp
    Arbitrum averages 4 blocks per second
    """
    seconds_diff = (target_block - ref_block) / 4
    return ref_block_timestamp + seconds_diff


def batch_populate_events_with_block_timestamps(
        web3_client: Web3Client,
        logger: logging,
        events: list[ProcessedEvent],
        max_requests_per_batch=1000,
):
    logger.perf.start("chunk_new_event_blocks")
    if len(events) == 0:
        return
    assert max_requests_per_batch > 0, "Expected max_requests_per_batch > 0"

    max_chunk_size = max_requests_per_batch

    blocks = list({event.block for event in events})

    logger.debug(
        "events: {}, requests_per_contract: {}, max_chunk_size: {}".format(
            len(blocks), max_requests_per_batch, max_chunk_size
        )
    )

    chunks = [blocks[i: i + max_chunk_size] for i in range(0, len(blocks), max_chunk_size)]
    logger.perf.end("chunk_new_event_blocks")

    logger.perf.start("fetch_new_event_block_timestamps total")
    responses = []
    for chunk in chunks:

        assert len(chunk) <= max_requests_per_batch, "Expected chunk size <= {} got {}".format(
            max_requests_per_batch, len(chunk)
        )

        logger.perf.start("fetch_new_event_block_timestamps of size {}".format(len(chunk)))
        with web3_client.web3.batch_requests() as batch:
            for block in chunk:
                batch.add(web3_client.web3.eth.get_block(block))

            res = batch.execute()
            responses.extend(res)
        logger.perf.end("fetch_new_event_block_timestamps of size {}".format(len(chunk)))

    assert (
            len(responses) == len(blocks)
    ), "Expected {} responses, got {}".format(len(blocks), len(responses))

    logger.debug("Fetched timestamps of blocks for {} events".format(len(blocks)))

    logger.perf.end("fetch_new_event_block_timestamps total")

    block_timestamps = {
        block_info["number"]: block_info["timestamp"]
        for block_info in responses
    }

    for event in events:
        event.timestamp = block_timestamps.get(event.block)
        if event.timestamp is None:
            logger.warning("No timestamp for block {}".format(event.block))

    return

def populate_events_with_main_arg(events: list[ProcessedEvent]):
    """
    Populates the main_arg field of the event with a main argument if one is specified, otherwise the value of the first argument.
    """
    for event in events:
        # NOTE: This is apparently the best way to get the 0th element of a dict
        event.main_arg = event.args[next(iter(event.args))]
