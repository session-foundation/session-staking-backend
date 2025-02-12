from contextlib import closing

from .dataclasses import PriceDB
from ..db.write import DBWriter


class DBWriterPrices(DBWriter):
    def __init__(self, db_path: str, log_level: int, perf: bool = False):
        super().__init__(db_path, log_level, perf)

    def write_prices_to_db(self, prices: list[PriceDB]):
        self.log.perf.start("write_prices_to_db")

        with closing(self.connect()) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:
                self.log.debug("Inserting {} prices".format(len(prices)))
                self.log.perf.start("write_prices_to_db -> insert prices")

                cursor.executemany(
                    """
                    INSERT INTO prices (token, currency, price, market_cap, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        (
                            price.token,
                            price.currency,
                            price.price,
                            price.market_cap,
                            price.updated_at,
                        )
                        for price in prices
                    ),
                )

                inserted_rows = cursor.rowcount

                self.log.perf.end("write_prices_to_db -> insert prices")
                self.log.debug("Inserted {} rows into prices".format(inserted_rows))

            connection.commit()
            self.log.perf.end("write_prices_to_db")

    def write_registration_to_db(self, registration):
        self.log.perf.start("write_registration_to_db")
        with closing(self.connect()) as connection:
            connection.execute("BEGIN")
            with closing(connection.cursor()) as cursor:
                self.log.debug("Inserting {} registration".format(len(registration)))
                self.log.perf.start("write_registration_to_db -> insert registration")

                cursor.execute(
                    """
                    INSERT OR REPLACE INTO registrations (
                        contract,
                        operator,
                        pubkey_bls,
                        pubkey_ed25519,
                        sig_bls,
                        sig_ed25519
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        registration.get("contract"),
                        registration.get("operator"),
                        registration.get("pubkey_bls"),
                        registration.get("pubkey_ed25519"),
                        registration.get("sig_bls"),
                        registration.get("sig_ed25519"),
                    ),
                )

                inserted_rows = cursor.rowcount

                self.log.perf.end("write_registration_to_db -> insert registration")
                self.log.debug("Inserted {} rows into registration".format(inserted_rows))

            connection.commit()
            self.log.perf.end("write_registration_to_db")
