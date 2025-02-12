import time

import pytest

default_stale_time = 2


@pytest.fixture()
def cache():
    from .cache import Cache
    return Cache(stale_time_seconds=default_stale_time)


def test_cache_init(cache):
    assert cache.default_stale_time_seconds == default_stale_time
    assert cache.store == {}
    assert cache.cache_expiry == {}


def test_cache_set(cache):
    cache.set_cache_value("test", "potato")
    assert cache.store == {"test": "potato"}

    cache_expiry = cache.cache_expiry
    assert int(cache_expiry.get("test")) == int(time.time() + default_stale_time)


def test_cache_clear_stale(cache):
    cache.set_cache_value("test", "potato")
    cache.clear_stale(time.time() + 2)
    assert cache.store == {}
    assert cache.cache_expiry == {}

def test_cache_normal(cache):
    def getter():
        return "potato"

    val = cache.get("test", getter)
    assert val == "potato"

def test_cache_stale_timestamp_expired(cache):
    cache.get("test", getter=lambda: "potato")
    assert int(cache.cache_expiry.get("test")) == int(time.time() + default_stale_time)
    assert int(cache.get_stale_timestamp("test")) == int(time.time() + default_stale_time)

def test_cache_large_invalidate(cache):
    def getter():
        return "potato"

    invalidate_timestamp = 99999999999999999999

    cache.set_cache_value("test", "potato", invalidate_timestamp=invalidate_timestamp)
    val = cache.get("test", getter)
    assert val == "potato"

    assert cache.cache_expiry.get("test") == invalidate_timestamp
