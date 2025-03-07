#!/usr/bin/env python3
from dataclasses import dataclass
from uwsgidecorators import timer

from ..staking.snapshot import DBSnapshot
from ..util.flask_utils import FlaskApp, FlaskAppConfig


@dataclass
class SnapshotAppConfig(FlaskAppConfig):
    sqlite_db: str = None
    sqlite_db_snapshot: str = None
    snapshot_time_interval_seconds: int = None
    snapshot_on_startup: bool = None


class App(FlaskApp):
    def __init__(self, config: SnapshotAppConfig):
        super().__init__(config)
        assert config.snapshot_time_interval_seconds >= 1, "Snapshot interval must be at least 1 second"

        self.db_snapshot = DBSnapshot(
            source_db_path=config.sqlite_db,
            snapshot_db_path=config.sqlite_db_snapshot,
            excluded_tables={
                # Staging rows, these are committed to the main db once the immutable height is reached, this can be synced by the end user
                "service_nodes_staging",
                "service_nodes_contributions_staging",
            },
            log_level=config.log_level,
            perf=config.enable_perf,
        )

        self.log.info(f"Snapshot task initialized, will run every {config.snapshot_time_interval_seconds} seconds.")


def create_app(config) -> App:
    app = App(config)

    @timer(config.snapshot_time_interval_seconds)
    def snapshot_db(signum):
        app.db_snapshot.snapshot()

    if config.snapshot_on_startup:
        app.log.info("Snapshotting database on startup, set snapshot_on_startup=False to disable")
        snapshot_db(None)

    return app
