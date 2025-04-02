#!/usr/bin/env python3

from src import config
from src.price.app import create_app, PriceAppConfig

price_config = PriceAppConfig(
    name="price_api",
    log_level=config.backend.log_level,
    enable_perf=config.backend.performance_logging,
    sqlite_db=config.backend.prices_sqlite_db,
    sqlite_schema=config.backend.prices_sqlite_schema,
    coingecko_api_key=config.backend.coingecko_api_key,
    coingecko_api_url=config.backend.coingecko_api_url,
    coingecko_api_token_ids=config.backend.coingecko_api_token_ids,
    coingecko_api_rate_poll_rate_seconds=config.backend.prices_api_refetch_interval_seconds,
    default_token=config.backend.prices_api_default_token,
    enable_price_fetcher=config.backend.enable_price_fetcher,
)

app = create_app(price_config)
