import asyncio
import logging
from dataclasses import dataclass
from math import ceil
from typing import Callable

from web3 import AsyncWeb3

from src.util.parse import get_relative_time_from_ms
from src.web3client.util import get_time_of_arbitrum_blocks_ms


@dataclass
class PastEventsFetchQueueItem:
    event: any
    handler: callable
    start_block: int | None


class EventQueueManager:
    def __init__(self, w3: AsyncWeb3, log: logging, start_block: int = 0, max_run_depth: int = 10, get_logs_cap: int = 0):
        self.processed_events = 0
        self.event_queue = []
        self.w3 = w3
        self.log = log
        self.start_block = start_block
        self.max_run_depth = max_run_depth
        self.get_logs_cap = get_logs_cap
        log.info(f"Event queue manager starting with start block {start_block}")
        log.debug(f"Event queue manager max run depth {max_run_depth}")

    def add_event(self, event: any, handler: Callable, start_block: int | None = None):
        if start_block is None:
            start_block = self.start_block
        self.event_queue.append(PastEventsFetchQueueItem(event=event, handler=handler, start_block=start_block))

    async def process_event_queue(self, start_block: int | None = None, current_block: int = 0):
        if start_block is None:
            start_block = self.start_block

        # Once a websocket subscription is made, any events will be queued to be processed by the websocket consumer. This
        # past event scan should be done right after the websocket subscription is made so the block number at this time
        # can be used for all past event scans.
        block_current = await self.w3.eth.block_number if current_block == 0 else current_block

        queue, self.event_queue = self.event_queue, []

        if len(queue) > 0:
            get_logs_calls = 0
            for e in queue:
                from_block = e.start_block if e.start_block else start_block
                e.get_logs_calls=(ceil((block_current - from_block) / self.get_logs_cap) if self.get_logs_cap > 0 else 1)
                get_logs_calls += e.get_logs_calls

            start_log_message = f"Fetching past events for {len(queue)} events, this will take {get_logs_calls} getLogs calls with get_logs_cap set to {self.get_logs_cap}"

            if get_logs_calls > 500:
                start_log_message += f" (this may take a while)"
                self.log.warning(start_log_message)
            else:
                self.log.info(start_log_message)

            responses = []
            for past_event in queue:
                from_block = past_event.start_block if past_event.start_block else start_block
                self.log.info(
                    f"Fetching past events for {past_event.event.event_name} from block {from_block} to block {block_current} ({block_current - from_block} blocks ~{get_relative_time_from_ms(get_time_of_arbitrum_blocks_ms(block_current - from_block))})")

                fetched_block = start_block - 1

                to_block = block_current if self.get_logs_cap == 0 else min(block_current, from_block + self.get_logs_cap)

                self.log.info(f"Fetching logs for {past_event.event.event_name} with get_logs_cap set to {self.get_logs_cap} will take {past_event.get_logs_calls} getLogs calls")

                while fetched_block < to_block:
                    self.log.info(f"Fetching logs for {past_event.event.event_name} from block {from_block} to block {to_block} ({to_block - from_block} blocks ~{get_relative_time_from_ms(get_time_of_arbitrum_blocks_ms(to_block - from_block))})")
                    for recent in await past_event.event.get_logs(from_block=from_block, to_block=to_block):
                        responses.append((recent, past_event.handler))
                    fetched_block = to_block
                    from_block = to_block + 1
                    to_block = block_current if self.get_logs_cap == 0 else min(block_current, from_block + self.get_logs_cap)
                self.processed_events += 1

            # sort responses by block then log index
            responses = sorted(responses, key=lambda x: (x[0].get("blockNumber"), x[0].get("logIndex")))

            handlers = []
            for (data, handler) in responses:
                handlers.append(handler(data))

            await asyncio.gather(*handlers)

        else:
            self.log.debug("No past events to fetch")

        return block_current

    async def run(self, current_block: int = 0):
        # The max depth ensures the loop won't get stuck in an infinite loop. This is just a safety measure as it should
        # not be possible due to the queue population dependencies.
        run_depth = 0
        last_scanned_block = 0
        while run_depth <= self.max_run_depth and len(self.event_queue) > 0:
            last_scanned_block = await self.process_event_queue(current_block=current_block)
            run_depth += 1

        logging.debug(
            f"Processed lifetime total of {self.processed_events} events")

        if run_depth > self.max_run_depth:
            self.log.warning(
                f"Reached max run depth of {self.max_run_depth}. This may indicate a problem with the event scanner. Events may have been missed.")

        return last_scanned_block