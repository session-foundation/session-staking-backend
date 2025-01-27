import time
import pytest
from registrations import app


@pytest.fixture()
def client():
    return app.test_client()


@pytest.mark.skip(reason="This is a utility function called by other tests")
def test_rate_limit(client, endpoint, method, reset=True, rate_limit=60, rate_limit_period=60):
    if reset:
        app.req_limiter.store = {}
        app.req_limiter.max_reqs_per_sec = rate_limit
        app.req_limiter.rate_limit_period = rate_limit_period

    req_fn = getattr(client, method)

    for _ in range(rate_limit):
        r = req_fn(endpoint)
        assert r.status_code == 200, "Responds with 200 when rate limit is not exceeded"

    r = req_fn(endpoint)
    assert r.status_code == 429, "Responds with 429 when rate limit is exceeded"


def test_rate_limit_get(client):
    test_rate_limit(client, "/info", "get")


def test_rate_limit_post(client):
    test_rate_limit(client, f"/store/0000000000000000000000000000000000000000000000000000000000000000", "post")


def test_rate_limit_resets(client):
    rate_limit_period = 1
    test_rate_limit(client, "/info", "get", rate_limit_period=rate_limit_period)
    time.sleep(rate_limit_period)
    test_rate_limit(client, "/info", "get", rate_limit_period=rate_limit_period, reset=False)

def test_rate_limit_separate_ips(client):
    test_rate_limit(client, "/info", "get")

    ip = list(app.req_limiter.store.keys())[0]
    ip_info = app.req_limiter.store[ip]

    app.req_limiter.store = {
        '1.1.1.1': ip_info
    }

    test_rate_limit(client, "/info", "get", reset=False)

    assert len(app.req_limiter.store.keys()) == 2
