import logging
import sqlite3


def init_db(db_path: str, schema_path: str):
    assert db_path is not None and len(db_path) > 0
    assert schema_path is not None and len(schema_path) > 0
    with sqlite3.connect(db_path) as conn:
        with open(schema_path, "r") as file:
            schema_sql = file.read()
        conn.executescript(schema_sql)


def is_db_initialized(db_path: str):
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        db_tables = cursor.fetchall()
        logging.debug(f"Database tables: {db_tables}")
        return len(db_tables) > 0


SQLITE_MAX_INT = 2**63 - 1  # 9,223,372,036,854,775,807
SQLITE_MIN_INT = -(2**63)  # -9,223,372,036,854,775,808


def assert_all_dict_values_are_within_sqlite_integer_range(node: dict):
    for key, value in node.items():
        if isinstance(value, int):
            assert (
                SQLITE_MIN_INT <= value <= SQLITE_MAX_INT
            ), f"Integer value {value} for key '{key}' in dict is out of SQLite integer range."


def sql_connect_in_read_mode(db_path: str):
    if not db_path.startswith("file:"):
        db_path = "file:" + db_path

    if not db_path.endswith("?mode=ro"):
        db_path = db_path + "?mode=ro"

    return sqlite3.connect(db_path, uri=True)

def sql_connect_in_write_mode(db_path: str): # Maybe dubious, but perhaps good for API symmetry, I'll defer to you
    return sqlite3.connect(db_path)