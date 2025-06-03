from contextlib import closing

from .dataclasses import PriceDB
from ..db.util import sql_connect_in_read_mode


def get_latest_price(db_path: str, token: str):
    with closing(sql_connect_in_read_mode(db_path)) as connection:
        with closing(connection.cursor()) as cursor:
            cursor.execute(
                """
                SELECT * FROM prices WHERE token = ? ORDER BY fetched_at DESC LIMIT 1
                """,
                (token,),
            )
            price = PriceDB(*cursor.fetchone())
            return price

def get_prices_since(db_path: str, token: str, timestamp: int):
    with closing(sql_connect_in_read_mode(db_path)) as connection:
        with closing(connection.cursor()) as cursor:
            cursor.execute(
                """
                SELECT * FROM prices WHERE token = ? AND updated_at >= ? ORDER BY updated_at DESC
                """,
                (token, timestamp),
            )
            prices = [PriceDB(*price) for price in cursor.fetchall()]
            return prices
