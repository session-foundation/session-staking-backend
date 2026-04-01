from contextlib import closing

from .dataclasses import PriceDB
from ..db.util import sql_connect_in_write_mode


def write_prices_to_db(db_path: str, prices: list[PriceDB]):
    with closing(sql_connect_in_write_mode(db_path)) as connection:
        connection.execute("BEGIN")
        with closing(connection.cursor()) as cursor:
            cursor.executemany(
                """
                INSERT INTO prices (token, price, market_cap, updated_at, fetched_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    (
                        price.token,
                        price.price,
                        price.market_cap,
                        price.updated_at,
                        price.fetched_at,
                    )
                    for price in prices
                ),
            )
        connection.commit()
