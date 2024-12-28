# Extended from https://web3py.readthedocs.io/en/stable/filters.html#example-code
"""A stateful event scanner for Ethereum-based blockchains using web3.py.

With the stateful mechanism, you can do one batch scan or incremental scans,
where events are added wherever the scanner left off.
"""
import json
import time
import logging
from dataclasses import dataclass
from typing import Tuple, Optional, Callable, List, Iterable, Dict, Any

from web3 import Web3, HTTPProvider
from web3.datastructures import AttributeDict
from web3.exceptions import Web3TypeError
from eth_abi.codec import ABICodec

# Currently this method is not exposed over official web3 API,
# but we need it to construct eth_getLogs parameters
from web3._utils.filters import construct_event_filter_params
from web3._utils.events import get_event_data

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


@dataclass
class ProcessedEvent:
    args: dict
    block: int
    main_arg: str | None
    name: str
    timestamp: None | int
    tx: str

    def __post_init__(self):
        self.args = json.loads(self.args) if type(self.args) == str else self.args


class EventScanner:
    """Scan blockchain for events and try not to abuse JSON-RPC API too much.

    Can be used for real-time scans, as it detects minor chain reorganisation and rescans.
    Unlike the easy web3.contract.Contract, this scanner can scan events from multiple contracts at once.
    For example, you can get all transfers from all tokens in the same scan.

    You *should* disable the default ``exception_retry_configuration`` on your provider for Web3,
    because it cannot correctly throttle and decrease the `eth_getLogs` block number range.
    """

    def __init__(
        self,
        provider_url: str,
        events: List,
        filters: Dict[str, Any],
        max_chunk_scan_size: int = 10_000,
        max_request_retries: int = 5,
        request_retry_seconds: float = 5,
        safety_blocks: int = 10,
    ):
        """
        :param events: List of web3 Event we scan
        :param filters: Filters passed to get_logs
        :param max_chunk_scan_size: JSON-RPC API limit in the number of blocks we query. (Recommendation: 10,000 for mainnet, 500,000 for testnets)
        :param max_request_retries: How many times we try to reattempt a failed JSON-RPC call
        :param request_retry_seconds: Delay between failed requests to let JSON-RPC server to recover
        """

        self.logger = logger
        provider = HTTPProvider(provider_url)
        # Disable the default JSON-RPC retry configuration
        # as it correctly cannot handle eth_getLogs block range
        provider.exception_retry_configuration = None
        self.w3 = Web3(provider)
        self.events = events
        self.filters = filters

        # Our JSON-RPC throttling parameters
        # self.min_scan_chunk_size = 10  # 12 s/block = 120 seconds period
        self.min_scan_chunk_size = 10  # 12 s/block = 120 seconds period
        self.max_scan_chunk_size = max_chunk_scan_size
        self.max_request_retries = max_request_retries
        self.request_retry_seconds = request_retry_seconds

        self.safety_blocks = safety_blocks

        # Factor how fast we increase the chunk size if results are found
        # # (slow down scan after starting to get hits)
        self.chunk_size_decrease = 0.5

        # Factor how fast we increase chunk size if no results found
        # self.chunk_size_increase = 2.0
        self.chunk_size_increase = 10.0

        # Start low at 20, this value is set at the end of the scan so we can use the optimal chunk size in future scans
        self.optimal_chunk_size = 20

    def scan_chunk(self, start_block, end_block) -> Tuple[int, list]:
        """Read and process events between to block numbers.

        Dynamically decrease the size of the chunk if the case JSON-RPC server pukes out.

        :return: tuple(actual end block number, when this block was mined, processed events)
        """

        all_processed = []

        # TODO: investigate sending all event types in a single call instead of looping over them
        for event_type in self.events:

            # Callable that takes care of the underlying web3 call
            def _fetch_events(_start_block, _end_block):
                return _fetch_events_for_all_contracts(
                    self.w3, event_type, self.filters, from_block=_start_block, to_block=_end_block
                )

            # Do `n` retries on `eth_getLogs`,
            # throttle down block range if needed
            end_block, events = _retry_web3_call(
                _fetch_events,
                start_block=start_block,
                end_block=end_block,
                retries=self.max_request_retries,
                delay=self.request_retry_seconds,
            )

            for evt in events:
                idx = evt[
                    "logIndex"
                ]  # Integer of the log index position in the block, null when its pending

                # We cannot avoid minor chain reorganisations, but
                # at least we must avoid blocks that are not mined yet
                assert idx is not None, "Somehow tried to scan a pending block"

                logger.debug(f"Processing event {evt['event']}, block: {evt['blockNumber']}")

                processed = self.process_event(evt)
                all_processed.append(processed)

        return end_block, all_processed

    def estimate_next_chunk_size(self, current_chuck_size: int, event_found_count: int):
        """Try to figure out optimal chunk size

        Our scanner might need to scan the whole blockchain for all events

        * We want to minimize API calls over empty blocks

        * We want to make sure that one scan chunk does not try to process too many entries once, as we try to control commit buffer size and potentially asynchronous busy loop

        * Do not overload node serving JSON-RPC API by asking data for too many events at a time

        Currently Ethereum JSON-API does not have an API to tell when a first event occurred in a blockchain
        and our heuristics try to accelerate block fetching (chunk size) until we see the first event.

        These heuristics exponentially increase the scan chunk size depending on if we are seeing events or not.
        When any transfers are encountered, we are back to scanning only a few blocks at a time.
        It does not make sense to do a full chain scan starting from block 1, doing one JSON-RPC call per 20 blocks.
        """
        current_chuck_size *= self.chunk_size_increase

        current_chuck_size = max(self.min_scan_chunk_size, current_chuck_size)
        current_chuck_size = min(self.max_scan_chunk_size, current_chuck_size)
        return int(current_chuck_size)

    def scan(
        self, start_block, end_block, progress_callback=Optional[Callable]
    ) -> Tuple[list, int]:
        """Perform a token balances scan.

        Assumes all balances in the database are valid before start_block (no forks sneaked in).

        :param start_block: The first block included in the scan

        :param end_block: The last block included in the scan

        :param start_chunk_size: How many blocks we try to fetch over JSON-RPC on the first attempt

        :param progress_callback: If this is an UI application, update the progress of the scan

        :return: [All processed events, number of chunks used]
        """

        assert start_block <= end_block

        current_block = start_block

        # Scan in chunks, commit between
        chunk_size = self.optimal_chunk_size
        last_scan_duration = last_logs_found = 0
        total_chunks_scanned = 0

        # All processed entries we got on this scan cycle
        all_processed = []

        while current_block <= end_block:

            # Print some diagnostics to logs to try to fiddle with real world JSON-RPC API performance
            estimated_end_block = min(current_block + chunk_size, end_block)
            logger.debug(
                f"Scanning events for blocks: {current_block} - {estimated_end_block}, chunk size {chunk_size}, last chunk scan took {last_scan_duration}, last logs found {last_logs_found}"
            )

            start = time.time()
            actual_end_block, new_entries = self.scan_chunk(current_block, estimated_end_block)

            # Where does our current chunk scan ends - are we out of chain yet?
            current_end = actual_end_block

            last_scan_duration = time.time() - start
            all_processed += new_entries

            if progress_callback:
                progress_callback(
                    start_block,
                    end_block,
                    current_block,
                    chunk_size,
                    len(new_entries),
                )

            # Try to guess how many blocks to fetch over `eth_getLogs` API next time
            chunk_size = self.estimate_next_chunk_size(chunk_size, len(new_entries))

            # Set where the next chunk starts
            current_block = current_end + 1
            total_chunks_scanned += 1

        self.optimal_chunk_size = chunk_size
        return all_processed, total_chunks_scanned

    def process_event(self, event: AttributeDict) -> ProcessedEvent:
        """Record a ERC-20 transfer in our database."""
        # Events are keyed by their transaction hash and log index
        # One transaction may contain multiple events
        # and each one of those gets their own log index
        # log_index = event.logIndex  # Log index within the block
        tx = event.transactionHash.hex()
        block = event.blockNumber
        name = event.event
        args = event["args"]
        return ProcessedEvent(tx=tx, block=block, name=name, args=args, timestamp=None, main_arg=None)

    def run(
        self,
        last_block: int,
        end_block: int,
        contract_creation_height=0,
    ):
        start = time.time()
        # Scan from [last block scanned] - [latest ethereum block]
        # Note that our chain reorg safety blocks cannot go negative
        start_block = max(last_block - self.safety_blocks, 0, contract_creation_height)
        blocks_to_scan = end_block - start_block

        print(f"Scanning events from blocks {start_block} - {end_block}")

        def _update_progress(start, end, current, chunk_size, events_count):
            print(
                f"Current block: {current}, blocks in a scan batch: {chunk_size}, events processed in a batch {events_count}"
            )

        # Run the scan
        result, total_chunks_scanned = self.scan(
            start_block, end_block, progress_callback=_update_progress
        )

        logger.debug(
            f"Scanned total {len(result)} events in {time.time() - start}, total {total_chunks_scanned} chunk scans performed"
        )

        return result


def _retry_web3_call(func, start_block, end_block, retries, delay) -> Tuple[int, list]:
    """A custom retry loop to throttle down block range.

    If our JSON-RPC server cannot serve all incoming `eth_getLogs` in a single request,
    we retry and throttle down block range for every retry.

    For example, Go Ethereum does not indicate what is an acceptable response size.
    It just fails on the server-side with a "context was cancelled" warning.

    :param func: A callable that triggers Ethereum JSON-RPC, as func(start_block, end_block)
    :param start_block: The initial start block of the block range
    :param end_block: The initial start block of the block range
    :param retries: How many times we retry
    :param delay: Time to sleep between retries
    """
    for i in range(retries):
        try:
            return end_block, func(start_block, end_block)
        except Exception as e:
            # Assume this is HTTPConnectionPool(host='localhost', port=8545): Read timed out. (read timeout=10)
            # from Go Ethereum. This translates to the error "context was cancelled" on the server side:
            # https://github.com/ethereum/go-ethereum/issues/20426
            if i < retries - 1:
                # Give some more verbose info than the default middleware
                logger.warning(
                    f"Retrying events for block range {start_block} - {end_block} ({end_block-start_block}) failed with {e} , retrying in {delay} seconds"
                )
                # Decrease the `eth_getBlocks` range
                end_block = start_block + ((end_block - start_block) // 2)
                # Let the JSON-RPC to recover e.g. from restart
                time.sleep(delay)
                continue
            else:
                logger.warning("Out of retries")
                raise


def _fetch_events_for_all_contracts(
    w3, event, argument_filters: Dict[str, Any], from_block: int, to_block: int
) -> Iterable:
    """Get events using eth_getLogs API.

    This method is detached from any contract instance.

    This is a stateless method, as opposed to create_filter.
    It can be safely called against nodes which do not provide `eth_newFilter` API, like Infura.
    """

    if from_block is None:
        raise Web3TypeError("Missing mandatory keyword argument to get_logs: from_block")

    # Currently no way to poke this using a public web3.py API.
    # This will return raw underlying ABI JSON object for the event
    abi = event._get_event_abi()

    # Depending on the Solidity version used to compile
    # the contract that uses the ABI,
    # it might have Solidity ABI encoding v1 or v2.
    # We just assume the default that you set on Web3 object here.
    # More information here https://eth-abi.readthedocs.io/en/latest/index.html
    codec: ABICodec = w3.codec

    # Here we need to poke a bit into Web3 internals, as this
    # functionality is not exposed by default.
    # Construct JSON-RPC raw filter presentation based on human readable Python descriptions
    # Namely, convert event names to their keccak signatures
    # More information here:
    # https://github.com/ethereum/web3.py/blob/e176ce0793dafdd0573acc8d4b76425b6eb604ca/web3/_utils/filters.py#L71
    data_filter_set, event_filter_params = construct_event_filter_params(
        abi,
        codec,
        address=argument_filters.get("address"),
        argument_filters=argument_filters,
        from_block=from_block,
        to_block=to_block,
    )

    logger.debug(f"Querying eth_getLogs with the following parameters: {event_filter_params}")

    # Call JSON-RPC API on your Ethereum node.
    # get_logs() returns raw AttributedDict entries
    logs = w3.eth.get_logs(event_filter_params)

    # Convert raw binary data to Python proxy objects as described by ABI
    all_events = []
    for log in logs:
        # Convert raw JSON-RPC log result to human readable event by using ABI data
        # More information how process_log works here
        # https://github.com/ethereum/web3.py/blob/fbaf1ad11b0c7fac09ba34baff2c256cffe0a148/web3/_utils/events.py#L200
        evt = get_event_data(codec, abi, log)
        # Note: This was originally yield,
        # but deferring the timeout exception caused the throttle logic not to work
        all_events.append(evt)
    return all_events
