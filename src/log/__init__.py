import logging

from .perf import PerformanceLogger
from .util import add_logging_level

CUSTOM_LOG_LEVELS = {"SILLY": 1, "PERFORMANCE": 69}
for label, lvl in CUSTOM_LOG_LEVELS.items():
    add_logging_level(label, lvl)


class CustomFormatter(logging.Formatter):

    green = "\x1b[32;20m"
    blue = "\x1b[36;20m"
    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    purple = "\x1b[35;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s | %(name)s | %(levelname)s | %(message)s (%(filename)s:%(lineno)d)"

    FORMATS = {
        CUSTOM_LOG_LEVELS["SILLY"]: green + format + reset,
        logging.DEBUG: blue + format + reset,
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset,
        69: purple + format + reset,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


class Log:
    def __init__(self, name, initial_level=CUSTOM_LOG_LEVELS["SILLY"], enable_perf=False):
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(initial_level)
        self.logger.propagate = False

        ch = logging.StreamHandler()
        ch.setLevel(initial_level)
        ch.setFormatter(CustomFormatter())
        self.logger.addHandler(ch)

        self.logger.perf = PerformanceLogger(self.logger, enable_perf)

    def set_level(self, level: str) -> None:
        named_level = logging.getLevelName(level)
        self.logger.info("Setting log level to {}".format(named_level))
        self.logger.setLevel(level)
