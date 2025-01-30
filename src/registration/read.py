import sqlite3
from contextlib import closing

from src.staking.dataclasses import Registration
from ..log import Log

class DBReaderRegistrations:
    def __init__(self, db_path: str, log_level: int, perf: bool = False):
        self.db_path = db_path
        self.log = Log("db_reader", log_level, enable_perf=perf).logger

    def get_registrations(self):
        self.log.perf.start("get_registrations")
        with closing(sqlite3.connect(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute(
                    """
                    SELECT * FROM registrations ORDER BY timestamp DESC
                    """
                )
                registrations = [Registration(*registration) for registration in cursor.fetchall()]
                self.log.debug("Registrations: {}".format(len(registrations)))
                self.log.perf.end("get_registrations")
                return registrations

    def get_registrations_for_operator(self, operator: bytes):
        self.log.perf.start("get_registrations_for_operator")
        with closing(sqlite3.connect(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute(
                    """
                    SELECT * FROM registrations WHERE operator = ? ORDER BY timestamp DESC
                    """,
                    (operator,),
                )
                registrations = [Registration(*registration) for registration in cursor.fetchall()]
                self.log.debug("Registrations: {}".format(len(registrations)))
                self.log.perf.end("get_registrations_for_operator")
                return registrations

    def get_registrations_by_pubkey(self, pubkey: bytes):
        self.log.perf.start("get_registrations_by_pubkey")
        with closing(sqlite3.connect(self.db_path)) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute(
                    """
                    SELECT * FROM registrations WHERE pubkey_ed25519 = ? ORDER BY timestamp DESC
                    """,
                    (pubkey,),
                )
                registrations = [Registration(*registration) for registration in cursor.fetchall()]
                self.log.debug("Registrations: {}".format(len(registrations)))
                self.log.perf.end("get_registrations_by_pubkey")
                return registrations
