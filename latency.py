import time

class LatencyTracker:

    def __init__(self):
        self._start = None
        self.timings = {}

    def start(self):
        self._start = time.perf_counter()
        self.timings = {}

    def mark(self, stage_name: str):
        elapsed = (time.perf_counter() - self._start) * 1000
        self.timings[stage_name] = round(elapsed, 2)

    def summary(self) -> dict:
        stages = list(self.timings.items())
        stage_durations = {}
        prev = 0
        for name, cumulative in stages:
            stage_durations[name] = round(cumulative - prev, 2)
            prev = cumulative
        return {
            "stage_durations_ms": stage_durations,
            "total_ms": stages[-1][1] if stages else 0,
        }