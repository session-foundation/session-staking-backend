#!/usr/bin/env python3

from src import config
from src.snapshot.app import create_app

app = create_app(config)