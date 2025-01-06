#!/usr/bin/env python3
import flask
import subprocess
from uwsgidecorators import timer
import config
from db.snapshot import DBSnapshot
from log import Log


class App(flask.Flask):
    def __init__(self, name):
        super().__init__(__name__)
        log = Log(name, enable_perf=config.backend.performance_logging)
        log.set_level(config.backend.log_level)
        git_rev = subprocess.run(
            ["git", "rev-parse", "--short=9", "HEAD"], stdout=subprocess.PIPE, text=True
        )
        self.git_rev = git_rev.stdout.strip() if git_rev.returncode == 0 else "(unknown)"

        self.log = log.logger

        assert config.backend.sqlite_snapshot_time_interval_seconds > 60, "Snapshot interval must be greater than 60 seconds"

        self.db_snapshot = DBSnapshot(
            source_db_path=config.backend.sqlite_db,
            snapshot_db_path=config.backend.sqlite_db_snapshot,
            excluded_tables={
                # Staging rows, these are committed to the main db once the immutable height is reached, this can be synced by the end user
                "service_nodes_staging",
                "service_nodes_contributions_staging",
            },
            log_level=config.backend.log_level,
            perf=config.backend.performance_logging,
        )

        self.log.info("Snapshot task initialized, will run every {} seconds.".format(config.backend.sqlite_snapshot_time_interval_seconds))


app = App(
    config.backend.snapshot_task_name if config.backend.snapshot_task_name else __name__
)


@timer(config.backend.sqlite_snapshot_time_interval_seconds)
def snapshot_db(signum):
    app.db_snapshot.snapshot()

if config.backend.snapshot_on_startup:
    snapshot_db(None)