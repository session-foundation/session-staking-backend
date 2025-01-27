#!/usr/bin/env python3
from dataclasses import dataclass
from uwsgidecorators import timer
from price.coingecko import CoinGeckoTokenPriceRequest
from price.read import DBReaderPrices, PriceDB
from price.write import DBWriterPrices
from util.flask_utils import FlaskApp, FlaskReqLimiter, json_response, FlaskAppConfig
from db.util import is_db_initialized, init_db


@dataclass
class PriceAppConfig(FlaskAppConfig):
    # Flask App Config
    sqlite_db: str = None
    sqlite_schema: str = None
    coingecko_api_key: str = None
    coingecko_api_url: str = None
    coingecko_api_token_ids: list[str] = None
    coingecko_api_currencies: list[str] = None

    # Route Config
    coingecko_api_rate_poll_rate_seconds: int = None
    default_token: str = None
    default_currency: str = None


class App(FlaskApp):
    def __init__(self, config: PriceAppConfig, name=__name__):
        super().__init__(config)

        if not is_db_initialized(config.sqlite_db):
            self.log.info(
                "Initializing database {} with schema {}".format(
                    config.sqlite_db, config.sqlite_schema
                )
            )
            init_db(
                config.sqlite_db, config.sqlite_schema
            )

        self.db_reader_prices = DBReaderPrices(
            db_path=config.sqlite_db,
            log_level=config.log_level,
            perf=config.enable_perf,
        )
        self.db_writer_prices = DBWriterPrices(
            db_path=config.sqlite_db,
            log_level=config.log_level,
            perf=config.enable_perf,
        )
        self.token_price_request = CoinGeckoTokenPriceRequest(
            logger=self.log,
            key=config.coingecko_api_key,
            url=config.coingecko_api_url,
            token_ids=config.coingecko_api_token_ids,
            currencies=config.coingecko_api_currencies,
            include_market_cap=True,
            include_last_updated_at=True,
        )


def create_app(config: PriceAppConfig):
    app = App(config)

    if config.api_rate_limit is not None and config.api_rate_limit_period is not None:
        @app.before_request
        def rate_limit():
            return app.req_limiter.rate_limit()

    price_poll_rate_seconds = config.coingecko_api_rate_poll_rate_seconds if config.coingecko_api_rate_poll_rate_seconds is not None else 0

    """
    //////////////////////////////////////////////////////////////
    //                                                          //
    //                    Price Endpoints                       //
    //                                                          //
    //////////////////////////////////////////////////////////////
    """

    def get_token_price_cache_key(token: str):
        return f"price-{token}-all"

    def get_token_info_cached(token: str):
        key = get_token_price_cache_key(token)

        data: dict[str, PriceDB] | None = app.cache.get_cached_only(key)

        if data:
            return data

        data = app.db_reader_prices.get_latest_prices(token)

        updated_at = max(price.updated_at for price in data.values())

        stale_time = updated_at + price_poll_rate_seconds
        app.cache.set_cache_value(key, data, invalidate_timestamp=stale_time)
        return data

    def get_price_for_token_uncached(params: [str, str]):
        return get_token_info_cached(params[0]).get(params[1])

    def get_price_for_token_cached(token: str, currency: str) -> PriceDB | None:
        return app.cache.get(f"price-{token}-{currency}", getter=get_price_for_token_uncached,
                             getter_args=[token, currency], ttl=1)

    def get_token_price_info(token: str = config.default_token):
        data = get_price_for_token_cached(token, config.default_currency)

        if data is None:
            return json_response({"error": "Failed to fetch price"})

        key = get_token_price_cache_key(token)
        stale_time = app.cache.get_stale_timestamp(key)

        return {
            "usd": data.price,
            "usd_market_cap": data.market_cap,
            "t_price": data.updated_at,
            "t_stale": stale_time,
        }

    @app.route("/price")
    def route_get_token_price():
        return json_response({
            "price": get_token_price_info()
        })

    @app.route("/price/<token>")
    def route_get_token_price_for_token(token: str):
        return json_response({
            "price": get_token_price_info(token)
        })

    if price_poll_rate_seconds > 0:
        app.log.info("Polling for price info every {} seconds".format(price_poll_rate_seconds))

        @timer(price_poll_rate_seconds)
        def fetch_token_price_info(signum):
            app.logger.info("Fetch token price info start")
            data = app.token_price_request.get()
            formatted_data = app.token_price_request.format_for_db(data)
            app.db_writer_prices.write_prices_to_db(formatted_data)
            app.logger.info("Fetch token price info finish")

        fetch_token_price_info(None)

    return app
