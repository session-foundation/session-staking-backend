import time

import flask
from flask import request


class FlaskReqLimiter:
    """
    Flask request limiter

    This is a simple request limiter that can be used to rate limit requests to a Flask app.
    It uses a simple in-memory store to keep track of the number of requests per IP address.

    Usage:
    ```
    from util.flask import FlaskReqLimiter

    app.req_limiter = FlaskReqLimiter(max_reqs_per_sec=100)

    @app.before_request
    def rate_limit():
        return app.req_limiter.rate_limit()
    ```
    """
    def __init__(self, max_reqs_per_sec: int = 100, rate_limit_period: int = 60):
        self.store = {}
        self.max_reqs_per_sec = max_reqs_per_sec
        self.rate_limit_period = rate_limit_period


    def rate_limit(self):
        now = time.time()
        ip_address = request.remote_addr
        requests, expire = self.store.get(ip_address, (0, now + self.rate_limit_period))

        if now > expire:
            self.store[ip_address] = (1, now + self.rate_limit_period)
            return

        if requests >= self.max_reqs_per_sec:
            return flask.abort(429)

        self.store[ip_address] = (requests + 1, expire)