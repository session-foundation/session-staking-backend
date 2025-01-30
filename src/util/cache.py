import logging
import time
from copy import copy
from typing import Optional, Callable

from ..log import Log


class Cache:
    def __init__(self, stale_time_seconds: int = 0, log_level: int = logging.INFO):
        self.log = Log("data_manager", log_level).logger
        self.default_stale_time_seconds = stale_time_seconds
        self.store = {}
        self.cache_expiry = {}

    def get(self, key, getter=Optional[Callable], getter_args=None, ttl=None, invalidate_timestamp=None):
        if ttl is None or ttl < 0:
            ttl = self.default_stale_time_seconds
        now = time.time()

        if key in self.store and self.cache_expiry.get(key, 0) > now:
            return self.store.get(key)

        self.clear_stale(now)

        data = getter(getter_args) if getter_args is not None else getter()
        self.set_cache_value(key, data, ttl, invalidate_timestamp)
        return data

    def get_cached_only(self, key: str):
        now = time.time()
        if key in self.store and self.cache_expiry.get(key, 0) > now:
            return self.store.get(key)
        return None

    def set_cache_value(self, key: str, data=None, ttl=None, invalidate_timestamp=None):
        now = time.time()
        if invalidate_timestamp is None:
            if ttl is None or ttl < 0:
                ttl = self.default_stale_time_seconds
            expire = now + ttl
        else:
            expire = invalidate_timestamp

        self.store[key] = data
        self.set_expiry_timestamp(key, expire)

    def set_expiry_ttl(self, key: str, ttl: int):
        self.cache_expiry[key] = time.time() + ttl

    def set_expiry_timestamp(self, key: str, timestamp: int):
        self.cache_expiry[key] = timestamp

    def get_stale_timestamp(self, key: str):
        return self.cache_expiry.get(key, 0)

    def clear_stale(self, now):
        # NOTE: must be a copy as the dictionary is modified during iteration
        for key, expiry in copy(self.cache_expiry).items():
            if expiry < now:
                del self.store[key]
                del self.cache_expiry[key]
