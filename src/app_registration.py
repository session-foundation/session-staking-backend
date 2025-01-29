#!/usr/bin/env python3

import config
from registration.app import create_app, RegistrationAppConfig

registration_config = RegistrationAppConfig(
    name="registration_api",
    log_level=config.backend.log_level,
    enable_perf=config.backend.performance_logging,
    sqlite_db=config.backend.registration_sqlite_db,
    sqlite_schema=config.backend.registration_sqlite_schema,
    api_rate_limit=config.backend.registration_api_rate_limit,
    api_rate_limit_period=config.backend.registration_api_rate_limit_period,
)

app = create_app(registration_config)