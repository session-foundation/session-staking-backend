import logging
import statistics
import time

from log import PerformanceLogger
from util import format_seconds, format_ms


class TimeKeeper:
    def __init__(self, logger: logging, perf=False, max_events=10_000):
        self.max_events = max_events
        assert self.max_events > 100, "max_events must be greater than 100 to be meaningful"
        assert self.max_events < 10e6, "max_events must be less than 10e6 to avoid memory issues"

        self.logger = logger

        self.time_keeper_app_alive = time.time()
        self.exec_timestamps = {}

        self.exec_durations = {}
        self.exec_cpu_durations = {}

        if perf:
            self.perf = PerformanceLogger(logger.perf, enabled=True)

    def add(self, name: str):
        self.exec_timestamps.setdefault(name, []).append(time.time())
        self.perf.start(name)

    def end(self, name: str):
        elapsed_ms, elapsed_cpu_ms = self.perf.end_timer(name)
        self.exec_durations.setdefault(name, []).append(elapsed_ms)
        self.exec_cpu_durations.setdefault(name, []).append(elapsed_cpu_ms)

    def get(self, name: str):
        return (
            self.exec_timestamps[name],
            self.exec_durations[name],
            self.exec_cpu_durations[name],
        )

    def log_time_keeper(self):
        self.logger.info(
            "Time keeper: app alive for {} seconds".format(
                format_seconds(time.time() - self.time_keeper_app_alive, 0)
            )
        )
        for task, timestamps in self.exec_timestamps.items():
            deltas = []
            for i in range(len(timestamps)):
                if i == 0:
                    continue
                deltas.append(timestamps[i] - timestamps[i - 1])

            n_deltas = len(deltas)

            self.logger.info("Time keeper: task '{}', n: {}".format(task, len(timestamps)))
            if n_deltas > 0:
                self.logger.info(
                    "- Intervals: min: {}s, max: {}s, avg: {}s, median: {}s, stddev: {}s".format(
                        format_seconds(min(deltas)),
                        format_seconds(max(deltas)),
                        format_seconds(sum(deltas) / n_deltas),
                        format_seconds(statistics.median(deltas)) if n_deltas > 1 else "N/A",
                        format_seconds(statistics.stdev(deltas)) if n_deltas > 1 else "N/A",
                    )
                )
            else:
                self.logger.info("- More than one timestamp is required for interval stats")

            durations = self.exec_durations[task]
            n_durations = len(durations)
            if n_durations > 0:
                self.logger.info(
                    "- Durations: min: {}ms, max: {}ms, avg: {}ms, median: {}ms, stddev: {}ms".format(
                        format_ms(min(durations)),
                        format_ms(max(durations)),
                        format_ms(sum(durations) / n_durations),
                        format_ms(statistics.median(durations)) if n_durations > 1 else "N/A",
                        format_ms(statistics.stdev(durations)) if n_durations > 1 else "N/A",
                    )
                )
            else:
                self.logger.info("- More than one duration is required for duration stats")

            cpu_durations = self.exec_cpu_durations[task]
            n_cpu_durations = len(cpu_durations)
            if len(cpu_durations) > 0:
                self.logger.info(
                    "- CPU Durations: min: {}ms, max: {}ms, avg: {}ms, median: {}ms, stddev: {}ms".format(
                        format_ms(min(cpu_durations)),
                        format_ms(max(cpu_durations)),
                        format_ms(sum(cpu_durations) / n_cpu_durations),
                        format_ms(statistics.median(cpu_durations)) if n_durations > 1 else "N/A",
                        (
                            format_ms(statistics.stdev(cpu_durations))
                            if n_cpu_durations > 1
                            else "N/A"
                        ),
                    )
                )
            else:
                self.logger.info("- More than one cpu duration is required for cpu duration stats")

        self.cleanup()

    def cleanup(self):
        # NOTE: each array can vary in length as if an error occurs, exec_timestamps will be longer than durations
        if len(self.exec_timestamps) > self.max_events:
            self.exec_timestamps = self.exec_timestamps[-self.max_events :]
        if len(self.exec_durations) > self.max_events:
            self.exec_durations = self.exec_durations[-self.max_events :]
        if len(self.exec_cpu_durations) > self.max_events:
            self.exec_cpu_durations = self.exec_cpu_durations[-self.max_events :]
