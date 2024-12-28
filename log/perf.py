import logging
import time


class PerformanceLogger:
    def __init__(self, logger: logging = None, enabled=True):
        if enabled:
            self.logger = logger
            self.start = self._start_enabled
            self.end = self.end_enabled
            self.end_timer = self.end_timer_enabled
            self.times = {}
            self.cpu_times = {}
            self.orphaned_event_age_seconds = 3600  # 1 hour
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
        elapsed_ms, elapsed_cpu_ms = self.end_timer(label)
        self._log_end(label, elapsed_ms, elapsed_cpu_ms)

    def end_timer_enabled(self, label):
        start_time = self.times.pop(label, None)
        start_time_cpu = self.cpu_times.pop(label, None)

        self._cleanup_orphans()

        if start_time is not None and start_time_cpu is not None:
            elapsed_ms = (time.perf_counter_ns() - start_time) / 1e6
            elapsed_cpu_ms = (time.process_time_ns() - start_time_cpu) / 1e6
            return elapsed_ms, elapsed_cpu_ms
        return None, None

    def _log_end(self, label, elapsed_ms, elapsed_cpu_ms):
        if self.logger is None:
            return

        if elapsed_ms is not None and elapsed_cpu_ms is not None:
            self.logger.performance(
                f"Elapsed time for '{label}': {elapsed_ms:.6f} ms ({elapsed_cpu_ms:.6f} cpu ms)"
            )
        else:
            self.logger.performance(f"No start time recorded for label '{label}'")

    def _cleanup_orphans(self):
        now = time.time()
        if len(self.times) > 0 and now - self.last_orphan_prune > self.check_for_orphans_interval:
            self.last_orphan_prune = now
            for label, start in self.times.items():
                if now - start > self.orphaned_event_age_seconds:
                    self.times.pop(label)

    def _noop(self, *args, **kwargs):
        pass
