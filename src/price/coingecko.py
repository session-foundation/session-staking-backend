import logging
import time

import requests

from .dataclasses import PriceDB


class CoinGeckoTokenPriceRequest:
    def __init__(self, logger: logging, key: str, url: str, token_ids: list[str], include_market_cap: bool = True, include_last_updated_at: bool = True, precision: int = 9):
        self.log = logger
        self.token_ids = token_ids
        self.headers = {
            "accept": "application/json",
            "x-cg-demo-api-key": key
        }

        query_params = {
            "ids": "%2C".join(token_ids),
            "vs_currencies": "%2C".join(['usd']),
        }

        if include_market_cap:
            query_params["include_market_cap"] = "true"

        if include_last_updated_at:
            query_params["include_last_updated_at"] = "true"

        if precision is not None:
            assert precision > 0
            query_params["precision"] = precision

        query_string = "&".join([f"{key}={value}" for key, value in query_params.items()])
        self.url = f"{url}/v3/simple/price?{query_string}"

    def get(self):
        """
        Fetch the latest token price info. Uses the params set in the constructor.

        Response looks like:
        {
          "arbitrum": {
            "usd": 0.704886,
            "usd_market_cap": 3061960433.734907,
            "aud": 1.12,
            "aud_market_cap": 4859220977.76168,
            "last_updated_at": 1737685901
          },
          "ethereum": {
            "usd": 3305.97,
            "usd_market_cap": 398379929097.7145,
            "last_updated_at": 1737685896
          }
        }
        """
        response = requests.get(self.url, headers=self.headers)

        if response.ok:
            return response.json()

        self.log.warning("Fetch token price info error: {}".format(response))
        return None

    def format_for_db(self, response: dict):
        """
        Converts the response from the CoinGecko API to a format that can be stored in the database.

        Example response:
        {
          "arbitrum": {
            "usd": 0.704886,
            "usd_market_cap": 3061960433.734907,
            "last_updated_at": 1737685901
          },
          "ethereum": {
            "usd": 3305.97,
            "usd_market_cap": 398379929097.7145,
            "last_updated_at": 1737685896
          }
        }
        """
        result = []

        for token in self.token_ids:
            if token not in response:
                self.log.warning(f"Token {token} not found in CoinGecko API response")
                continue

            fetched_at = int(time.time())
            updated_at = response[token].get("last_updated_at", None)
            market_cap = response[token].get(f"usd_market_cap", None)
            price = response[token].get("usd", None)
            if price is None:
                self.log.warning(f"USD price not found in CoinGecko API response for token {token}")

            result.append(PriceDB(token=token, price=price, market_cap=market_cap, updated_at=updated_at, fetched_at=fetched_at))

        return result

