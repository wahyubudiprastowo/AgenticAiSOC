from __future__ import annotations

import threading
import time


class RemoteCircuitBreaker:
    """Thread-safe closed/open/half-open circuit with a fixed cooldown."""

    def __init__(self, cooldown_seconds: float):
        self.cooldown_seconds = max(0.0, float(cooldown_seconds))
        self._lock = threading.Lock()
        self._state = "closed"
        self._retry_at = 0.0

    def begin(self, now: float | None = None) -> tuple[bool, str | None]:
        current = time.monotonic() if now is None else now
        with self._lock:
            if self._state == "closed":
                return True, None
            remaining = self._retry_at - current
            if self._state == "open" and remaining > 0:
                return False, f"upstream circuit open; retry in {remaining:.1f}s"
            if self._state == "open":
                self._state = "half_open"
                return True, None
            return False, "upstream circuit half-open probe is already in progress"

    def finish(self, success: bool, now: float | None = None) -> None:
        current = time.monotonic() if now is None else now
        with self._lock:
            if success:
                self._state = "closed"
                self._retry_at = 0.0
            else:
                self._state = "open"
                self._retry_at = current + self.cooldown_seconds

    def snapshot(self, now: float | None = None) -> dict:
        current = time.monotonic() if now is None else now
        with self._lock:
            return {
                "circuit_state": self._state,
                "retry_after_seconds": (
                    round(max(0.0, self._retry_at - current), 1)
                    if self._state == "open" else 0.0
                ),
            }
