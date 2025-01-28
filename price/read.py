import sqlite3
from contextlib import closing
from attr import dataclass

from ..log import Log


@dataclass
class PriceDB:
    token: str
    currency: str
    price: float
    market_cap: float
    updated_at: int


class DBReaderPrices:
    def __init__(self, db_path: str, log_level: int, perf: bool = False):
        self.db_path = db_path
        self.log = Log("db_reader", log_level, enable_perf=perf).logger

    def get_latest_price(self, token: str, currency: str):
        self.log.perf.start("get_latest_price")
        with closing(sqlite3.connect(self.db_path)) as connection:
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
        with closing(sqlite3.connect(self.db_path)) as connection:
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
        with closing(sqlite3.connect(self.db_path)) as connection:
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
