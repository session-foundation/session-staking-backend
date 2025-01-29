import os
import sys

def import_config():
    sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
    from src import config
    # reset system path to original state
    sys.path.pop()
    return config