import sqlite3

from src.log import Log

class DBWriter:
    def __init__(self, db_path: str, log_level: int, perf: bool = False):
        self.db_path = db_path
        self.log = Log("db_writer", log_level, enable_perf=perf).logger
        self.log.info(f"Connecting to db at {db_path}")

    def connect(self):
        return sqlite3.connect(self.db_path)
