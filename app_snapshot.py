#!/usr/bin/env python3

import config
from snapshot.app import create_app

app = create_app(config)