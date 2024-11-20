import logging
from dataclasses import dataclass

import eth_utils

from web3client.client import Web3Client
from web3client.contracts.service_node_contribution import ServiceNodeContributionInterface
from web3client.contracts.service_node_contribution_factory import ServiceNodeContributionFactory
from web3client.contracts.service_node_rewards import ServiceNodeRewardsInterface


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
    logger.perf.end("get_new_contribution_contracts")
    return contracts, events


@dataclass
class ContributionContractDetails:
    address: str | None
    fee: int | None
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

        for j in range(len(contributions_addresses)):
            contributions_list.append(
                {
                    "contract_address": contract_address,
                    "address": contributions_addresses[j],
                    "amount": contributions_amounts[j],
                    "beneficiary_address": contributions_beneficiaries[j],
                }
            )

        status = responses[i + 4]

        contract_details.append(
            ContributionContractDetails(
                address=contract_address,
                service_node_pubkey=f"{params[0]:032x}",
                service_node_signature=f"{params[1]:032x}{params[2]:032x}",
                fee=params[3],
                operator_address=operator_address,
                pubkey_bls="0x{:0128x}".format((pubkey_bls_data[0] << 256) + pubkey_bls_data[1]),
                status=status,
            )
        )

    logger.debug("Fetched details for {} contracts".format(len(contract_details)))

    logger.perf.end("fetch_contribution_contract_details total")
    return contract_details, contributions_list
