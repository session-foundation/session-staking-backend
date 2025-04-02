from contextlib import closing

from .dataclasses import PriceDB
from ..db.util import sql_connect_in_read_mode


def get_latest_price(db_path: str, token: str):
    with closing(sql_connect_in_read_mode(db_path)) as connection:
        with closing(connection.cursor()) as cursor:
            cursor.execute(
                """
                SELECT * FROM prices WHERE token = ? ORDER BY updated_at DESC LIMIT 1
                """,
                (token,),
            )
            price = PriceDB(*cursor.fetchone())
            return price
