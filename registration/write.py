import sqlite3
from contextlib import closing

from log import Log


class DBWriterRegistrations:
    def __init__(self, db_path: str, log_level: int, perf: bool = False):
        self.db_path = db_path
        self.log = Log("db_writer", log_level, enable_perf=perf).logger

    def write_registration_to_db(self, registration):
        self.log.perf.start("write_registration_to_db")
        with closing(sqlite3.connect(self.db_path)) as connection:
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
