#!/usr/bin/env python3
from uwsgidecorators import timer

from ..db.snapshot import DBSnapshot
from ..util.flask_utils import FlaskApp


class App(FlaskApp):
    def __init__(self, config):
        name = config.backend.snapshot_task_name if config.backend.snapshot_task_name else __name__
        super().__init__(name, enable_perf=config.backend.performance_logging,
                         log_level=config.backend.log_level)

        assert config.backend.sqlite_snapshot_time_interval_seconds > 29, "Snapshot interval must be greater than 29 seconds"

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

        self.log.info("Snapshot task initialized, will run every {} seconds.".format(
            config.backend.sqlite_snapshot_time_interval_seconds))


def create_app(config) -> App:
    app = App(config)

    @timer(config.backend.sqlite_snapshot_time_interval_seconds)
    def snapshot_db(signum):
        app.db_snapshot.snapshot()

    if config.backend.snapshot_on_startup:
        snapshot_db(None)

    return app
