#!/usr/bin/env python3
import time
from dataclasses import dataclass
from math import trunc

import flask

from ..util.flask_utils import FlaskApp, json_response, FlaskAppConfig
from .coingecko import CoinGeckoTokenPriceRequest
from .read import get_latest_price, get_prices_since
from .dataclasses import PriceDB
from .write import write_prices_to_db
from ..db.util import is_db_initialized, init_db


@dataclass
class PriceAppConfig(FlaskAppConfig):

    enable_price_fetcher: bool = False

    # Flask App Config
    disable_db_file_rewrite: bool = False
    sqlite_db: str = None
    sqlite_schema: str = None
    coingecko_api_key: str = None
    coingecko_api_url: str = None
    coingecko_api_token_ids: list[str] = None
    coingecko_precision: int = None

    # Route Config
    price_poll_rate_seconds: int = None
    default_token: str = None


class App(FlaskApp):
    def __init__(self, config: PriceAppConfig):
        super().__init__(config)
        self.app_config = config

        if config.enable_price_fetcher:
            self.log.info(f"Price fetcher enabled, fetching from {config.coingecko_api_url}")
            if not is_db_initialized(config.sqlite_db):
                self.log.info(f"Initializing database {config.sqlite_db} with schema {config.sqlite_schema}")
                init_db(config.sqlite_db, config.sqlite_schema)
        else:
            self.log.info("Price fetcher disabled. Set enable_price_fetcher to True to enable price fetcher.")

        if not config.default_token:
            config.default_token = config.coingecko_api_token_ids[0]
            self.log.warning(f"No default token set, using {config.default_token}")
        else:
            self.log.info(f"Default token set to {config.default_token}")

        self.db_path = config.sqlite_db

        if config.enable_price_fetcher:
            self.token_price_request = CoinGeckoTokenPriceRequest(
                logger=self.log,
                key=config.coingecko_api_key,
                url=config.coingecko_api_url,
                token_ids=config.coingecko_api_token_ids,
                include_market_cap=True,
                include_last_updated_at=True,
                precision=config.coingecko_precision,
            )

        self.price_poll_rate_seconds = config.price_poll_rate_seconds if config.price_poll_rate_seconds is not None else 0


    @staticmethod
    def get_token_price_cache_key(token: str):
        return f"price-{token}-all"

    @staticmethod
    def get_token_prices_cache_key_range(token: str, timestamp: int):
        return f"price-range-{token}-{timestamp}"


    def get_price_for_token_cached(self, token: str) -> PriceDB | None:
        key = self.get_token_price_cache_key(token)
        value = self.cache.get_cached_only(key)

        if value is None:
            value = get_latest_price(self.db_path, token)

        if value is None:
            return None

        self.cache.set_cache_value(key, value, invalidate_timestamp=value.updated_at + self.app_config.price_poll_rate_seconds)

        return value


    def get_token_price_info(self, token: str = None):
        if token is None:
            token = self.app_config.default_token

        if token not in self.app_config.coingecko_api_token_ids:
            return flask.abort(404, f"Token {token} not found!")

        data = self.get_price_for_token_cached(token)

        if data is None:
            return flask.abort(500, f"Failed to fetch price for token {token}")

        stale_time = trunc(self.cache.get_stale_timestamp(self.get_token_price_cache_key(token)))

        return {
            "usd": data.price,
            "usd_market_cap": data.market_cap,
            "t_price": data.updated_at,
            "t_stale": stale_time,
        }

    def get_prices_for_token_cached(self, token: str, range_seconds: int) -> list[PriceDB]:
        key = self.get_token_prices_cache_key_range(token, range_seconds)
        value = self.cache.get_cached_only(key)

        if value is None:
            value = get_prices_since(self.db_path, token, trunc(time.time()) - range_seconds)

        if len(value) > 0:
            self.cache.set_cache_value(key, value, invalidate_timestamp=value[0].updated_at + self.app_config.price_poll_rate_seconds)

        return value

def create_app(config: PriceAppConfig) -> App:
    app = App(config)

    if config.api_rate_limit is not None and config.api_rate_limit_period is not None:
        @app.before_request
        def rate_limit():
            return app.req_limiter.rate_limit()

    """
    //////////////////////////////////////////////////////////////
    //                                                          //
    //                    Price Endpoints                       //
    //                                                          //
    //////////////////////////////////////////////////////////////
    """

    @app.route("/price")
    def route_get_token_price():
        return json_response({
            "price": app.get_token_price_info()
        })

    @app.route("/price/<token>")
    def route_get_token_price_for_token(token: str):
        return json_response({
            "price": app.get_token_price_info(token)
        })

    def get_token_price_range_response(token: str, range_seconds: int):
        return json_response({
            "prices": app.get_prices_for_token_cached(token, range_seconds)
        })

    @app.route("/prices/<token>/<str:period>")
    def route_get_token_prices_for_token_range(token: str, period: str):
        match period:
            case "1h":
                return get_token_price_range_response(token, 60 * 60)
            case "1d":
                return get_token_price_range_response(token, 60 * 60 * 24)
            case "7d":
                return get_token_price_range_response(token, 60 * 60 * 24 * 7)
            case "30d":
                return get_token_price_range_response(token, 60 * 60 * 24 * 30)
            case _:
                return flask.abort(400, f"Invalid period {period}")


    if config.enable_price_fetcher:
        app.log.info("Polling for price info every {} seconds".format(app.price_poll_rate_seconds))
        try:
            from uwsgidecorators import timer
        except ModuleNotFoundError as e:
            if e.name == "uwsgi":
                app.log.error("uwsgi is not installed, run with uwsgi or disable price polling")
            raise e

        @timer(app.price_poll_rate_seconds)
        def fetch_token_price_info(signum):
            app.logger.info("Fetch token price info start")
            data = app.token_price_request.get()
            formatted_data = app.token_price_request.format_for_db(data)
            write_prices_to_db(app.db_path, formatted_data)
            app.logger.info("Fetch token price info finish")

        fetch_token_price_info(None)

    return app
