import sqlite3

from ..log import Log

class DBReader:
    def __init__(self, db_path: str, log_level: int, perf: bool = False, disable_db_file_rewrite: bool = False):
        self.log = Log("db_reader", log_level, enable_perf=perf).logger

        if not disable_db_file_rewrite:
            if not db_path.startswith("file:"):
                db_path = "file:" + db_path

            if not db_path.endswith("?mode=ro"):
                db_path = db_path + "?mode=ro"

        self.db_path = db_path

    def connect(self):
        self.log.info(f"Connecting to db at {self.db_path}")
        return sqlite3.connect(self.db_path, uri=True)
