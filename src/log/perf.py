import logging
import time
from copy import copy


class PerformanceLogger:
    def __init__(self, logger: logging = None, enabled=True):
        if enabled:
            assert logger is not None, "PerformanceLogger requires a logger when enabled=True"
            self.logger = logger
            self.start = self._start_enabled
            self.end = self.end_enabled
            self.end_timer = self.end_timer_enabled
            self.times = {}
            self.cpu_times = {}
            self.orphaned_event_age_ns = 3600 * 10**9  # 1 hour
            self.check_for_orphans_interval = 3600  # 1 hour
            self.last_orphan_prune = 0
        else:
            self.logger = None
            self.start = self._noop
            self.end = self._noop
            self.end_timer = self._noop

    def _start_enabled(self, label):
        self.times[label] = time.perf_counter_ns()
        self.cpu_times[label] = time.process_time_ns()

    def end_enabled(self, label):
        elapsed_ms, elapsed_cpu_ms = self.end_timer_enabled(label)
        self._log_end(label, elapsed_ms, elapsed_cpu_ms)

    def end_timer_enabled(self, label):
        start_time = self.times.pop(label, None)
        start_time_cpu = self.cpu_times.pop(label, None)


        if start_time is not None and start_time_cpu is not None:
            process_time_ns = time.perf_counter_ns()
            self._cleanup_orphans(process_time_ns)

            elapsed_ms = (process_time_ns - start_time) / 1e6
            elapsed_cpu_ms = (time.process_time_ns() - start_time_cpu) / 1e6
            return elapsed_ms, elapsed_cpu_ms
        return None, None

    def _log_end(self, label, elapsed_ms, elapsed_cpu_ms):
        if elapsed_ms is not None and elapsed_cpu_ms is not None:
            self.logger.performance(
                f"Elapsed time for '{label}': {elapsed_ms:.6f} ms ({elapsed_cpu_ms:.6f} cpu ms)"
            )
        else:
            self.logger.performance(f"No start time recorded for label '{label}'")

    def _cleanup_orphans(self, process_time_ns):
        if len(self.times) > 0 and process_time_ns - self.last_orphan_prune > self.check_for_orphans_interval:
            self.last_orphan_prune = process_time_ns

            # NOTE: must be a copy as the dictionary is modified during iteration
            for label, start in copy(self.times).items():
                if process_time_ns > start + self.orphaned_event_age_ns:
                    self.times.pop(label)

    def _noop(self, *args, **kwargs):
        pass
