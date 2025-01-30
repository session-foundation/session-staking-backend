from contextlib import closing

from .dataclasses import PriceDB
from ..db.read import DBReader


class DBReaderPrices(DBReader):
    def __init__(self, db_path: str, log_level: int, perf: bool = False):
        super().__init__(db_path, log_level, perf)

    def get_latest_price(self, token: str, currency: str):
        self.log.perf.start("get_latest_price")
        with closing(self.connect()) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute(
                    """
                    SELECT * FROM prices WHERE token = ? AND currency = ? ORDER BY updated_at DESC LIMIT 1
                    """,
                    (token, currency),
                )
                price = PriceDB(*cursor.fetchone())
                self.log.debug("Price: {}".format(price))
                self.log.perf.end("get_latest_price")
                return price

    def get_latest_prices(self, token: str):
        self.log.perf.start("get_latest_prices")
        with closing(self.connect()) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute(
                    """
                    SELECT * FROM prices WHERE token = ? ORDER BY updated_at DESC
                    """,
                    (token,),
                )
                prices_lst = [PriceDB(*price) for price in cursor.fetchall()]

                prices = {
                    price.currency: price for price in prices_lst
                }

                self.log.debug("Prices: {}".format(len(prices)))
                self.log.perf.end("get_latest_prices")
                return prices

    def get_unique_currencies(self, token: str):
        self.log.perf.start("get_unique_currencies")
        with closing(self.connect()) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute(
                    """
                    SELECT DISTINCT currency FROM prices WHERE token = ?
                    """,
                    (token,),
                )
                currencies = [currency[0] for currency in cursor.fetchall()]
                self.log.debug("Currencies: {}".format(len(currencies)))
                self.log.perf.end("get_unique_currencies")
                return currencies
