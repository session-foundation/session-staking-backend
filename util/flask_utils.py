import subprocess
import time
import flask
from util.cache import Cache
from log import Log
from util.parse import hexify


def json_response(vals = None, vals_no_hexify=None):
    """
    Takes a dict, adds some general info fields to it, and jsonifies it for a flask route function
    return value.  The dict gets passed through `hexify` first to convert any bytes values to hex.

    Note: because network_info is cached, it can be called earlier in the route and both network_info
     dict will be the same in both places, and basically guaranteed cached at this stage.
    """
    if vals is None:
        vals = {}
    else:
        hexify(vals)

    if vals_no_hexify is None:
        vals_no_hexify = {}

    return flask.jsonify({**vals, **vals_no_hexify, "t": time.time()})


class FlaskApp(flask.Flask):
    def __init__(self, name: str, log_level: str, log_level_generic: str | None = None, enable_perf: bool = False,
                 cache_stale_time_seconds: int = 0):
        super().__init__(__name__)
        log = Log(name, enable_perf=enable_perf)
        log.set_level(log_level)
        self.log = log.logger

        git_rev = subprocess.run(
            ["git", "rev-parse", "--short=9", "HEAD"], stdout=subprocess.PIPE, text=True
        )
        self.git_rev = git_rev.stdout.strip() if git_rev.returncode == 0 else "(unknown)"

        # Creates a generic logger to pipe other packages logs into the main app logger
        if log_level_generic is not None:
            generic_logger = Log(None)
            generic_logger.set_level(log_level_generic)

        self.cache = Cache(stale_time_seconds=cache_stale_time_seconds)


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
        ip_address = flask.request.remote_addr
        requests, expire = self.store.get(ip_address, (0, now + self.rate_limit_period))

        if now > expire:
            self.store[ip_address] = (1, now + self.rate_limit_period)
            return

        if requests >= self.max_reqs_per_sec:
            return flask.abort(429)

        self.store[ip_address] = (requests + 1, expire)
