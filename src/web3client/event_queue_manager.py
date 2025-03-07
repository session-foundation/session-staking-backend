import asyncio
import logging
from dataclasses import dataclass
from typing import Callable

from web3 import AsyncWeb3
from web3.utils.subscriptions import LogsSubscription

from src.util.parse import get_relative_time_from_ms
from src.web3client.util import get_time_of_arbitrum_blocks_ms


@dataclass
class PastEventsFetchQueueItem:
    event: any
    handler: callable
    start_block: int | None


class EventQueueManager:
    def __init__(self, w3: AsyncWeb3, log: logging, start_block: int = 0, max_run_depth: int = 10):
        self.processed_events = 0
        self.processed_subs = 0
        self.sub_queue = []
        self.event_queue = []
        self.w3 = w3
        self.log = log
        self.start_block = start_block
        self.max_run_depth = max_run_depth
        log.info(f"Event queue manager starting with start block {start_block}")
        log.debug(f"Event queue manager max run depth {max_run_depth}")

    def add_event(self, event: any, handler: Callable, start_block: int | None = None):
        if start_block is None:
            start_block = self.start_block
        self.event_queue.append(PastEventsFetchQueueItem(event=event, handler=handler, start_block=start_block))

    def add_subscription(self, sub: LogsSubscription):
        self.sub_queue.append(sub)

    def add(self, event: any, handler: Callable, sub: LogsSubscription, start_block: int | None = None):
        self.add_subscription(sub)
        self.add_event(event, handler, start_block)

    async def process_event_queue(self, start_block: int | None = None):
        if start_block is None:
            start_block = self.start_block

        # Once a websocket subscription is made, any events will be queued to be processed by the websocket consumer. This
        # past event scan should be done right after the websocket subscription is made so the block number at this time
        # can be used for all past event scans.
        block_current = await self.w3.eth.block_number

        queue, self.event_queue = self.event_queue, []

        if len(queue) > 0:
            self.log.info(f"Fetching past events for {len(queue)} events")

            responses = []
            for past_event in queue:
                from_block = past_event.start_block if past_event.start_block else start_block
                self.log.debug(
                    f"Fetching past events for {past_event.event.event_name} from block {from_block} to block {block_current} ({block_current - from_block} blocks ~{get_relative_time_from_ms(get_time_of_arbitrum_blocks_ms(block_current - from_block))})")
                for recent in await past_event.event.get_logs(from_block=from_block, to_block=block_current):
                    responses.append(past_event.handler(recent))
                self.processed_events += 1

            await asyncio.gather(*responses)

        else:
            self.log.debug("No past events to fetch")

    async def process_sub_queue(self):
        sub_queue, self.sub_queue = self.sub_queue, []

        if len(sub_queue) > 0:
            await self.w3.subscription_manager.subscribe(sub_queue)
            self.processed_subs += len(sub_queue)
            self.log.info(f"Subscribed to {len(sub_queue)} subscriptions")
        else:
            self.log.debug("No subscriptions to subscribe to")

    async def run(self):
        # The max depth ensures the loop won't get stuck in an infinite loop. This is just a safety measure as it should
        # not be possible due to the queue population dependencies.
        run_depth = 0
        while run_depth <= self.max_run_depth and (len(self.sub_queue) > 0 or len(self.event_queue) > 0):
            await self.process_sub_queue()
            await self.process_event_queue()
            run_depth += 1

        logging.debug(
            f"Processed lifetime total of {self.processed_events} events and {self.processed_subs} subscriptions")

        if run_depth > self.max_run_depth:
            self.log.warning(
                f"Reached max run depth of {self.max_run_depth}. This may indicate a problem with the event scanner. Events may have been missed.")
