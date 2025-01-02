import logging
import oxenmq
import json
import sys
from datetime import datetime, timedelta


class RPCUsageTracker:
    def __init__(self, enabled: bool, log: logging):
        self.log = log
        if enabled:
            self.log.warning("RPC usage tracking enabled. This is not recommended for production use.")
            self.uses_success = {}
            self.uses_failed = {}
            self.uses_cached = {}
            self.add_success = self.add_success_enabled
            self.add_failed = self.add_failed_enabled
            self.add_cached = self.add_cached_enabled
            self.log_usage = self.log_usage_enabled

        else:
            self.add_success = self._noop
            self.add_failed = self._noop
            self.add_cached = self._noop
            self.log_usage = self._noop

    def _noop(self, *args, **kwargs):
        pass

    def add_success_enabled(self, endpoint: str):
        self.uses_success.setdefault(endpoint, []).append(datetime.now().timestamp())

    def add_failed_enabled(self, endpoint: str):
        self.uses_failed.setdefault(endpoint, []).append(datetime.now().timestamp())

    def add_cached_enabled(self, endpoint: str):
        self.uses_cached.setdefault(endpoint, []).append(datetime.now().timestamp())

    def log_usage_enabled(self):
        self.log.info("RPC usage tracking: (s/f/c {}/{}/{})".format(len(self.uses_success), len(self.uses_failed), len(self.uses_cached)))
        unique_endpoints: dict[str, dict[str, list[float]]] = {}

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
            stats_success = timestamps["success"]
            stats_failed = timestamps["failed"]
            stats_cached = timestamps["cached"]

            total_success = len(stats_success)
            total_failure = len(stats_failed)
            total_cached = len(stats_cached)

            total = total_success + total_failure + total_cached
            if total == 0:
                continue

            timestamps_all = stats_success + stats_failed + stats_cached
            timestamps_all.sort()

            ts_first = timestamps_all[0]
            ts_last = timestamps_all[-1]
            ts_delta = ts_last - ts_first

            if ts_delta == 0:
                continue

            avg_rpm = total / ts_delta

            now = datetime.now().timestamp()

            last_hour_timestamps = [t for t in timestamps_all if t > now - 3600]
            last_10_minutes_timestamps = [t for t in last_hour_timestamps if t > now - 600]

            avg_rpm_last_hour = len(last_hour_timestamps) / 3600
            avg_rpm_last_10_minutes = len(last_10_minutes_timestamps) / 600

            self.log.info(f"Endpoint: {endpoint}")
            self.log.info(f"  Total: {total} ({total_success} success, {total_failure} failure, {total_cached} cached)")
            self.log.info(f"  RPM: {avg_rpm} avg (last hour: {avg_rpm_last_hour}, last 10m: {avg_rpm_last_10_minutes})")


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
                oxend, self.endpoint, [] if self.args is None else [self.args], timeout=timeout
            )
        self.cache_seconds = cache_seconds
        self.rpc_usage_tracker = rpc_usage_tracker

    def get(self):
        """If the result is already available, returns it immediately (and can safely be called multiple times.
        Otherwise waits for the result, parses as json, and caches it.  Returns None if the request fails
        """
        if self.json is None and self.future is not None:
            try:
                result = self.future.get()
                self.future = None
                if result[0] != b"200":
                    self.rpc_usage_tracker.add_failed(self.endpoint)
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
        else:
            self.rpc_usage_tracker.add_cached(self.endpoint)

        return self.json

