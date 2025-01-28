import subprocess
import time
from dataclasses import dataclass
import flask
from werkzeug.middleware.proxy_fix import ProxyFix

from ..util.cache import Cache
from ..log import Log
from ..util.parse import hexify


def json_response(vals=None, vals_no_hexify=None):
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


@dataclass
class FlaskAppConfig:
    name: str
    log_level: int
    log_level_generic: str | None = None
    enable_perf: bool | None = False
    cache_stale_time_seconds: int = 0
    api_rate_limit: int | None = None
    api_rate_limit_period: int | None = None


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


class FlaskApp(flask.Flask):
    def __init__(self, config: FlaskAppConfig):
        super().__init__(config.name)
        log = Log(config.name, enable_perf=config.enable_perf)
        log.set_level(config.log_level)
        self.log = log.logger

        git_rev = subprocess.run(
            ["git", "rev-parse", "--short=9", "HEAD"], stdout=subprocess.PIPE, text=True
        )
        self.git_rev = git_rev.stdout.strip() if git_rev.returncode == 0 else "(unknown)"

        # Creates a generic logger to pipe other packages logs into the main app logger
        if config.log_level_generic is not None:
            generic_logger = Log(None)
            generic_logger.set_level(config.log_level_generic)

        self.cache = Cache(stale_time_seconds=config.cache_stale_time_seconds)

        if config.api_rate_limit is not None and config.api_rate_limit_period is not None:
            self.log.info(f"IP Rate limit: {config.api_rate_limit} per {config.api_rate_limit_period} seconds")
            self.wsgi_app = ProxyFix(self.wsgi_app)
            self.req_limiter = FlaskReqLimiter(max_reqs_per_sec=config.api_rate_limit,
                                               rate_limit_period=config.api_rate_limit_period)
