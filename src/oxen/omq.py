import logging
from collections import defaultdict

import oxenmq
import json
import sys
from datetime import datetime, timedelta

def format_table(table: list[list[str| float | int]]):
    """
    Formats a table of values into a string.
    :param table: list of lists of values
    :return: string
    """
    # stringify every value in the table
    table = [[str(v) for v in row] for row in table]
    # find the maximum width of each column
    column_widths = [max(len(row[i]) for row in table) for i in range(len(table[0]))]
    # pad each column to the maximum width
    padded_table = [[row[i].ljust(column_widths[i]) for i in range(len(row))] for row in table]
    # join each row with a space separator
    padded_table = ["    ".join(row) for row in padded_table]
    # join each row with a newline separator
    return "\n".join(padded_table)

def bin_histogram_timestamps(timestamps, bin_size_seconds):
    """
    Bins a histogram of timestamps into a histogram of bins of size 'bin_size_seconds'.

    :param timestamps: list of timestamps
    :param bin_size_seconds: size of each bin in seconds
    :return: dict of bins to counts
    """
    bins = defaultdict(int)
    for t in timestamps:
        t_int = int(t)
        bin_key = t_int // bin_size_seconds
        bins[bin_key] += 1

    max_count_adjusted = 0
    max_count_timestamp = 0
    for k, v in bins.items():
        if v > max_count_adjusted:
            max_count_adjusted = v / bin_size_seconds
            max_count_timestamp = k * bin_size_seconds

    return bins, max_count_timestamp, max_count_adjusted

class RPCUsageTracker:
    def __init__(self, enabled: bool, log: logging):
        self.log = log
        if enabled:
            self.log.warning("RPC usage tracking enabled. This is not recommended for production use.")
            self.uses_executed = {}
            self.uses_success = {}
            self.uses_failed = {}
            self.uses_cached = {}
            self.fail_reasons = {}

            self.add_executed = self.add_executed_enabled
            self.add_success = self.add_success_enabled
            self.add_failed = self.add_failed_enabled
            self.add_cached = self.add_cached_enabled
            self.log_usage = self.log_usage_enabled

        else:
            self.add_executed = self._noop
            self.add_success = self._noop
            self.add_failed = self._noop
            self.add_cached = self._noop
            self.log_usage = self._noop

    def _noop(self, *args, **kwargs):
        pass

    def add_executed_enabled(self, endpoint: str):
        if endpoint not in self.uses_executed:
            self.uses_executed[endpoint] = 0
        self.uses_executed[endpoint] += 1

    def add_success_enabled(self, endpoint: str):
        self.uses_success.setdefault(endpoint, []).append(datetime.now().timestamp())

    def add_failed_enabled(self, endpoint: str, reason: str):
        self.uses_failed.setdefault(endpoint, []).append(datetime.now().timestamp())
        self.fail_reasons.setdefault(endpoint, []).append(reason)

    def add_cached_enabled(self, endpoint: str):
        self.uses_cached.setdefault(endpoint, []).append(datetime.now().timestamp())

    def log_usage_enabled(self, msg: str = ""):
        unique_endpoints: dict[str, dict[str, list[float]]] = {}

        g_executed = 0
        g_successes = 0
        g_failures = 0
        g_cached = 0

        for endpoint, timestamps in self.uses_success.items():
            unique_endpoints.setdefault(endpoint, {"success": [], "failed": [], "cached": []})
            unique_endpoints[endpoint]["success"].extend(timestamps)

        for endpoint, timestamps in self.uses_failed.items():
            unique_endpoints.setdefault(endpoint, {"success": [], "failed": [], "cached": []})
            unique_endpoints[endpoint]["failed"].extend(timestamps)

        for endpoint, timestamps in self.uses_cached.items():
            unique_endpoints.setdefault(endpoint, {"success": [], "failed": [], "cached": []})
            unique_endpoints[endpoint]["cached"].extend(timestamps)

        for endpoint, timestamps in unique_endpoints.items():
            log_lines = []
            stats_success = timestamps["success"]
            stats_failed = timestamps["failed"]
            stats_cached = timestamps["cached"]

            total_success = len(stats_success)
            total_failure = len(stats_failed)
            total_cached = len(stats_cached)


            g_successes += total_success
            g_failures += total_failure
            g_cached += total_cached

            total_executed = self.uses_executed.get(endpoint, 0)
            g_executed += total_executed

            total_completed = total_success + total_failure + total_cached
            if total_completed == 0:
                continue

            success_rate = total_success / total_completed
            failure_rate = total_failure / total_completed
            cache_rate = total_cached / total_completed

            fail_reasons = self.fail_reasons.get(endpoint, [])

            fail_timeout = 0
            fail_other = 0
            for reason in fail_reasons:
                if reason == "Timeout":
                    fail_timeout += 1
                else:
                    fail_other += 1

            fail_timeout_rate = fail_timeout / total_failure if total_failure > 0 else 0
            fail_other_rate = fail_other / total_failure if total_failure > 0 else 0

            timestamps_all = stats_success + stats_failed + stats_cached
            timestamps_all.sort()

            ts_first = timestamps_all[0]
            ts_last = timestamps_all[-1]
            total_time_seconds = ts_last - ts_first

            if total_time_seconds == 0:
                continue

            current_time = datetime.now().timestamp()

            # ---- 1. Average RPS over all time ----
            rps_avg = total_completed / total_time_seconds

            # ---- 2. Average RPS in the last hour ----
            one_hour_ago = current_time - 3600
            last_hour_timestamps = [ts for ts in timestamps_all if ts >= one_hour_ago]
            # If you want a simple “count / 3600”, do:
            rps_avg_last_hour = len(last_hour_timestamps) / 3600.0

            # ---- 3. Average RPS in the last 10 minutes (600 seconds) ----
            ten_minutes_ago = current_time - 600
            last_10m_timestamps = [ts for ts in last_hour_timestamps if ts >= ten_minutes_ago]
            rps_avg_last_10_minutes = len(last_10m_timestamps) / 600.0

            # ---- 4. Average RPS in the last 1 minute (60 seconds) ----
            one_minute_ago = current_time - 60
            last_1m_timestamps = [ts for ts in last_10m_timestamps if ts >= one_minute_ago]
            rps_avg_last_1_minute = len(last_1m_timestamps) / 60.0

            # ---- 5. Peak RPS over the past hour ----
            (h_1h_sec, rps_peak_time_1h_sec, rps_peak_1h_sec) = bin_histogram_timestamps(last_hour_timestamps, bin_size_seconds=1)
            (h_1h_min, rps_peak_time_1h_min, rps_peak_1h_min) = bin_histogram_timestamps(last_hour_timestamps, bin_size_seconds=60)

            # ---- 6. Peak RPS over the past hour binned every 10 minutes----
            (h_10m_sec, rps_peak_time_10m_sec, rps_peak_10m_sec) = bin_histogram_timestamps(last_10m_timestamps, bin_size_seconds=1)
            (h_10m_min, rps_peak_time_10m_min, rps_peak_10m_min) = bin_histogram_timestamps(last_10m_timestamps, bin_size_seconds=60)

            log_lines.append(f"\n{endpoint} | {total_executed} executed | {total_completed} completed ({success_rate:.2%} success ({total_success}) | {failure_rate:.2%} failure ({total_failure}) | {cache_rate:.2%} cached ({total_cached}))")
            log_lines.append(f"Timeout failures:  {fail_timeout_rate:.2%} of failures ({fail_timeout} / {total_failure}))")
            log_lines.append(f"Other failures:  {fail_other_rate:.2%} of failures ({fail_other} / {total_failure}))")

            stats = [
                ["Period", "#", "RPS", "Peak RPS (1s bin)", "Peak RPS Time (1s bin)", "Peak RPS (1m bin)",
                 "Peak RPS Time (1m bin)"],
                [f"Life ({total_time_seconds:.0f}s)", f"{total_completed}", f"{rps_avg:.2f}", "", "", "", ""],
                [f"< 1h", len(last_hour_timestamps), f"{rps_avg_last_hour:.2f}", f"{rps_peak_1h_sec:.2f}",
                 rps_peak_time_1h_sec, f"{rps_peak_1h_min:.2f}", rps_peak_time_1h_min],
                [f"< 10m", len(last_10m_timestamps), f"{rps_avg_last_10_minutes:.2f}", f"{rps_peak_10m_sec:.2f}",
                 rps_peak_time_10m_sec, f"{rps_peak_10m_min:.2f}", rps_peak_time_10m_min],
                [f"< 1m", len(last_1m_timestamps), f"{rps_avg_last_1_minute:.2f}", "", "", "", ""]]

            log_lines.append(format_table(stats))

            # self.log.info(f"  Requests in past {total} ({total_success} success, {total_failure} failure, {total_cached} cached)")
            # self.log.info(f"  Avg requests per second: {rps_avg:.2f} avg (last hour: {rps_avg_last_hour:.2f}, last 10m: {rps_avg_last_10_minutes:.2f})")
            msg += ("\n".join(log_lines))

        g_completed = g_successes + g_failures + g_cached
        g_success_rate = g_successes / g_completed if g_completed > 0 else 0
        g_failure_rate = g_failures / g_completed if g_completed > 0 else 0
        g_cache_rate = g_cached / g_completed if g_completed > 0 else 0

        header_msg = f"\nRPC usage tracking | {g_executed} executed | {g_completed} completed ({g_success_rate:.2%} success ({g_successes}) | {g_failure_rate:.2%} failure ({g_failures}) | {g_cache_rate:.2%} cached ({g_cached}))"
        self.log.info(header_msg + msg)

    def write_failure_reasons_to_file(self, filename: str):
        with open(filename, "w") as f:
            for endpoint, timestamps in self.fail_reasons.items():
                f.write(f"{endpoint}\n")
                for reason in timestamps:
                    f.write(f"  {reason}\n")

omq, oxend = None, None


def omq_connection(oxend_rpc):
    global omq, oxend
    if omq is None:
        omq = oxenmq.OxenMQ(log_level=oxenmq.LogLevel.warn)
        omq.max_message_size = 200 * 1024 * 1024
        omq.start()
    if oxend is None:
        oxend = omq.connect_remote(oxenmq.Address(oxend_rpc))
    return (omq, oxend)


cached = {}
cached_args = {}
cache_expiry = {}


class FutureJSON:
    """Class for making a OMQ JSON RPC request that uses a future to wait on the result, and caches
    the results for a set amount of time so that if the same endpoint with the same arguments is
    requested again the cache will be used instead of repeating the request.

    Cached values are indexed by endpoint and optional key, and require matching arguments to the
    previous call.  The cache_key should generally be a fixed value (*not* an argument-dependent
    value) and can be used to provide multiple caches for different uses of the same endpoint.
    Cache entries are *not* purged, they are only replaced, so using dynamic data in the key would
    result in unbounded memory growth.

    omq - the omq object
    oxend - the oxend omq connection id object
    endpoint - the omq endpoint, e.g. 'rpc.get_info'
    cache_seconds - how long to cache the response; can be None to not cache it at all
    cache_key - fixed string to enable different caches of the same endpoint
    args - if not None, a value to pass (after converting to JSON) as the request parameter. Typically a dict.
    fail_okay - can be specified as True to make failures silent (i.e. if failures are sometimes expected for this request)
    timeout - maximum time to spend waiting for a reply
    """

    def __init__(
        self,
        omq,
        oxend,
        endpoint,
        cache_seconds=5,
        *,
        cache_key="",
        args=None,
        fail_okay=False,
        timeout=10,
        rpc_usage_tracker: RPCUsageTracker = RPCUsageTracker(False, None),
    ):
        if timeout is None:
            timeout = 10
        self.endpoint = endpoint
        self.cache_key = self.endpoint + cache_key
        self.fail_okay = fail_okay
        if args is not None:
            args = json.dumps(args).encode()
        if (
            self.cache_key in cached
            and cached_args[self.cache_key] == args
            and cache_expiry[self.cache_key] >= datetime.now()
        ):
            self.json = cached[self.cache_key]
            self.args = None
            self.future = None
        else:
            self.json = None
            self.args = args
            self.future = omq.request_future(
                oxend, self.endpoint, [] if self.args is None else [self.args], request_timeout=timedelta(seconds=timeout)
            )
        self.cache_seconds = cache_seconds
        self.rpc_usage_tracker = rpc_usage_tracker

    def get(self):
        """If the result is already available, returns it immediately (and can safely be called multiple times.
        Otherwise waits for the result, parses as json, and caches it.  Returns None if the request fails
        """
        self.rpc_usage_tracker.add_executed(self.endpoint)
        if self.json is None and self.future is not None:
            try:
                result = self.future.get()
                self.future = None
                if result[0] != b"200":
                    raise RuntimeError(
                        "Request for {} failed: got {}".format(self.endpoint, result)
                    )
                self.json = json.loads(result[1])
                if self.cache_seconds is not None:
                    cached[self.cache_key] = self.json
                    cached_args[self.cache_key] = self.args
                    cache_expiry[self.cache_key] = datetime.now() + timedelta(
                        seconds=self.cache_seconds
                    )
                self.rpc_usage_tracker.add_success(self.endpoint)
            except RuntimeError as e:
                if not self.fail_okay:
                    print("Something getting wrong: {}".format(e), file=sys.stderr)
                self.future = None
                self.rpc_usage_tracker.add_failed(self.endpoint, e)

            except TimeoutError as e:
                if not self.fail_okay:
                    print("Timeout: {}".format(e), file=sys.stderr)
                self.future = None
                self.rpc_usage_tracker.add_failed(self.endpoint, "Timeout")

            except Exception as e:
                if not self.fail_okay:
                    print("Something getting wrong: {}".format(e), file=sys.stderr)
                self.future = None
                self.rpc_usage_tracker.add_failed(self.endpoint, e)
        else:
            self.rpc_usage_tracker.add_cached(self.endpoint)

        return self.json

