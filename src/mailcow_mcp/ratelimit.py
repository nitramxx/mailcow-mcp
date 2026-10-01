"""In-memory sliding-window rate limits (the app runs as a single process)."""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable


class RateLimiter:
    """Allows ``limit`` events per ``window`` seconds for each key."""

    def __init__(
        self, limit: int, window: float, *, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.limit = limit
        self.window = window
        self._clock = clock
        self._events: dict[str, deque[float]] = {}
        self._calls = 0

    def _recent(self, key: str, now: float) -> deque[float]:
        events = self._events.get(key)
        if events is None:
            events = self._events[key] = deque()
        while events and events[0] <= now - self.window:
            events.popleft()
        return events

    def allowed(self, key: str) -> bool:
        """Whether one more event for ``key`` is within the limit (doesn't record it)."""
        now = self._clock()
        return len(self._recent(key, now)) < self.limit

    def hit(self, key: str) -> bool:
        """Record an event; False if it exceeds the limit (then it isn't recorded)."""
        now = self._clock()
        self._maybe_prune(now)
        events = self._recent(key, now)
        if len(events) >= self.limit:
            return False
        events.append(now)
        return True

    def reset(self, key: str) -> None:
        self._events.pop(key, None)

    def _maybe_prune(self, now: float) -> None:
        # Bound memory: drop idle keys every 1000 calls.
        self._calls += 1
        if self._calls % 1000:
            return
        for key in [k for k, v in self._events.items() if not v or v[-1] <= now - self.window]:
            del self._events[key]
