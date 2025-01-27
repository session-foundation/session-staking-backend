#!/usr/bin/env python3
from uwsgidecorators import timer
from price.coingecko import CoinGeckoTokenPriceRequest
from price.read import DBReaderPrices, PriceDB
from price.write import DBWriterPrices
from util.flask_utils import FlaskApp, FlaskReqLimiter, json_response
from werkzeug.middleware.proxy_fix import ProxyFix
from db.util import is_db_initialized, init_db


class App(FlaskApp):
    def __init__(self, config):
        name = config.backend.prices_api_name if config.backend.prices_api_name else __name__
        super().__init__(name, enable_perf=config.backend.performance_logging,
                         log_level=config.backend.log_level, log_level_generic=config.backend.log_level_generic,
                         cache_stale_time_seconds=config.backend.stale_time_seconds)

        if not is_db_initialized(config.backend.prices_sqlite_db):
            self.log.info(
                "Initializing database {} with schema {}".format(
                    config.backend.prices_sqlite_db, config.backend.prices_sqlite_schema
                )
            )
            init_db(
                config.backend.prices_sqlite_db, config.backend.prices_sqlite_schema
            )

        self.db_reader = DBReaderPrices(
            db_path=config.backend.prices_sqlite_db,
            log_level=config.backend.log_level,
            perf=config.backend.performance_logging,
        )
        self.db_writer = DBWriterPrices(
            db_path=config.backend.prices_sqlite_db,
            log_level=config.backend.log_level,
            perf=config.backend.performance_logging,
        )
        self.token_price_request = CoinGeckoTokenPriceRequest(
            logger=self.log,
            key=config.backend.coingecko_api_key,
            url=config.backend.coingecko_api_url,
            token_ids=config.backend.coingecko_api_token_ids,
            currencies=config.backend.coingecko_api_currencies,
            include_market_cap=True,
            include_last_updated_at=True,
        )

        self.log.info(
            f"IP Rate limit: {config.backend.prices_api_rate_limit} per {config.backend.prices_api_rate_limit_period} seconds")
        self.log.info(
            "Polling for price info every {} seconds".format(config.backend.prices_api_refetch_interval_seconds))


def create_app(config):
    app = App(config)

    # Enables more reliable proxy pass through for rate limiting
    app.wsgi_app = ProxyFix(app.wsgi_app)
    app.req_limiter = FlaskReqLimiter(max_reqs_per_sec=config.backend.prices_api_rate_limit,
                                      rate_limit_period=config.backend.prices_api_rate_limit_period)

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

    def get_token_price_cache_key(token: str):
        return f"price-{token}-all"

    def get_token_info_cached(token: str):
        key = get_token_price_cache_key(token)

        data: dict[str, PriceDB] | None = app.cache.get_cached_only(key)

        if data:
            return data

        data = app.db_reader.get_latest_prices(token)

        updated_at = max(price.updated_at for price in data.values())

        stale_time = updated_at + config.backend.prices_api_refetch_interval_seconds
        app.cache.set_cache_value(key, data, invalidate_timestamp=stale_time)
        return data

    def get_price_for_token_uncached(params: [str, str]):
        return get_token_info_cached(params[0]).get(params[1])

    def get_price_for_token_cached(token: str, currency: str) -> PriceDB | None:
        return app.cache.get(f"price-{token}-{currency}", getter=get_price_for_token_uncached,
                             getter_args=[token, currency], ttl=1)

    def get_token_price_info(token: str = config.backend.prices_api_default_token):
        data = get_price_for_token_cached(token,
                                          config.backend.prices_api_default_currency)

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

    @timer(config.backend.prices_api_refetch_interval_seconds)
    def fetch_token_price_info(signum):
        app.logger.info("Fetch token price info start")
        data = app.token_price_request.get()
        formatted_data = app.token_price_request.format_for_db(data)
        app.db_writer.write_prices_to_db(formatted_data)
        app.logger.info("Fetch token price info finish")

    fetch_token_price_info(None)

    return app
