#!/usr/bin/env python3
from src import config
from src.staking.fetcher import App

app = App("fetcher")
app.run()
