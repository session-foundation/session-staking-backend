#!/usr/bin/env python3

from src import config
from src.snapshot.app import create_app, SnapshotAppConfig

snapshot_app_config = SnapshotAppConfig(
    name="snapshot",
    log_level=config.backend.log_level,
    enable_perf=config.backend.performance_logging,
    sqlite_db=config.backend.sqlite_db,
    log_level_generic=config.backend.log_level_generic,
    cache_stale_time_seconds=config.backend.stale_time_seconds,
    sqlite_db_snapshot=config.backend.sqlite_db_snapshot,
    snapshot_on_startup=config.backend.snapshot_on_startup,
    snapshot_time_interval_seconds=config.backend.snapshot_time_interval_seconds,
)

app = create_app(snapshot_app_config)