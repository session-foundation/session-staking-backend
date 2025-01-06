import os
import sqlite3
from log import Log


class DBSnapshot:
    def __init__(self, source_db_path: str, snapshot_db_path: str, excluded_tables: set[str] | None, log_level: int,
                 perf: bool = False):
        assert source_db_path is not None and len(source_db_path) > 0
        assert snapshot_db_path is not None and len(snapshot_db_path) > 0

        self.path_source = source_db_path
        self.path_snapshot = snapshot_db_path
        self.path_snapshot_tmp = snapshot_db_path + ".tmp"
        self.excluded_tables = excluded_tables if excluded_tables is not None else set()
        self.log = Log("db_snapshot", log_level, enable_perf=perf).logger

        os.makedirs(os.path.dirname(self.path_snapshot), exist_ok=True)

        self.log.info("Initializing snapshot task for DB. Source DB: {}, Snapshot DB: {}, Excluded tables: {}".format(
            self.path_source, self.path_snapshot, self.excluded_tables))

    def cleanup(self) -> None:
        """
        Removes the temporary snapshot DB if it exists.
        """
        self.log.perf.start("cleanup")
        self.log.info("Cleaning up tmp snapshot database {}".format(self.path_snapshot_tmp))
        if os.path.exists(self.path_snapshot_tmp):
            os.remove(self.path_snapshot_tmp)
        self.log.perf.end("cleanup")

    def promote_tmp_db(self) -> None:
        """
        Swaps the temporary snapshot DB with the final snapshot DB.
        """
        self.log.perf.start("promote_tmp_db")
        self.log.info("Swapping tmp snapshot database {} with final snapshot database {}".format(self.path_snapshot_tmp,
                                                                                                 self.path_snapshot))
        if os.path.exists(self.path_snapshot):
            os.remove(self.path_snapshot)
        os.rename(self.path_snapshot_tmp, self.path_snapshot)
        self.log.perf.end("promote_tmp_db")

    def snapshot(self) -> None:
        """
        Creates all tables from source_db_path into backup_db_path,
        but does NOT copy the row data for any tables listed in self.excluded_tables.
        """

        # Open (or create) the new backup DB
        self.log.perf.start("backup_db")
        self.log.info("Backing up database {} to {}".format(self.path_source, self.path_snapshot))

        self.cleanup()

        with sqlite3.connect(self.path_snapshot_tmp) as backup_conn:
            self.log.perf.start("backup_db_create_tables")
            # Attach the source database so we can refer to it as 'old_db'
            backup_conn.execute(f"ATTACH DATABASE '{self.path_source}' AS old_db;")
            # Gather tables and their CREATE TABLE statements from the source
            schema_query = """
                SELECT name, sql
                FROM old_db.sqlite_master
                WHERE type='table'
                      AND name NOT LIKE 'sqlite_%'  -- skip internal or system tables
            """
            tables = backup_conn.execute(schema_query).fetchall()

            # 1. Create all tables in the new DB
            for table_name, create_sql in tables:
                # Make sure there's a valid CREATE statement
                if create_sql:
                    backup_conn.execute(create_sql)

            self.log.perf.end("backup_db_create_tables")
            self.log.perf.start("backup_db_copy_rows")

            # 2. For each table, copy rows unless it's in tables_without_rows
            for table_name, _ in tables:
                if table_name not in self.excluded_tables:
                    # Insert rows from the source's table
                    insert_sql = f"""
                        INSERT INTO {table_name}
                        SELECT * FROM old_db.{table_name}
                    """
                    backup_conn.execute(insert_sql)
                else:
                    # We create the table above, but do NOT copy any rows for this table
                    print(f"Skipping rows for table: {table_name}")

            self.log.perf.end("backup_db_copy_rows")

            backup_conn.commit()

            # Detach the source database
            backup_conn.execute("DETACH DATABASE old_db;")

        self.promote_tmp_db()

        self.log.info("Backed up database {} to {}".format(self.path_source, self.path_snapshot))
        self.log.perf.end("backup_db")
