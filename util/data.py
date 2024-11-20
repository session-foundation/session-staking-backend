import time
from typing import Optional, Callable


class DataManager:
    def __init__(self, stale_time_seconds: int = 0):
        self.cache = {}
        self.cache_expiry = {}
        self.default_stale_time_seconds = stale_time_seconds

    def get(self, key, getter=Optional[Callable], getter_args=None, ttl=0):
        if ttl == 0:
            ttl = self.default_stale_time_seconds
        now = time.time()
        if key in self.cache and self.cache_expiry[key] > now:
            return self.cache[key]

        data = getter(getter_args) if getter_args is not None else getter()
        self.cache[key] = data
        self.cache_expiry[key] = now + ttl
        return data
