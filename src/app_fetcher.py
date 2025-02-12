#!/usr/bin/env python3
from src import config
from src.staking.fetcher import App

app = App(config.backend.fetcher_name if config.backend.fetcher_name else __name__)
app.run()