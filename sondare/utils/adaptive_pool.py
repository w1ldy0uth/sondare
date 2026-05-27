import threading

_WINDOW_SIZE = 20
_TIMEOUT_THRESHOLD = 0.5
_MIN_TIMEOUT = 0.5
_RTT_MULTIPLIER = 2.5


class _AdaptiveSemaphore:
    """Semaphore whose concurrency limit can be raised or lowered at runtime."""

    def __init__(self, initial: int, maximum: int) -> None:
        self._limit = initial
        self._max = maximum
        self._active = 0
        self._cond = threading.Condition(threading.Lock())

    def acquire(self) -> None:
        with self._cond:
            while self._active >= self._limit:
                self._cond.wait()
            self._active += 1

    def release(self) -> None:
        with self._cond:
            self._active -= 1
            self._cond.notify_all()

    def set_limit(self, n: int) -> None:
        with self._cond:
            self._limit = max(1, min(n, self._max))
            self._cond.notify_all()

    @property
    def limit(self) -> int:
        return self._limit


class AdaptivePool:
    """
    RTT-based timeout adaptation with optional AIMD concurrency control.

    Every WINDOW_SIZE probe outcomes, updates the timeout floor using the
    average RTT of successful probes.

    When adapt_concurrency=True, also applies AIMD to the thread limit:
      - rate > TIMEOUT_THRESHOLD  → halve concurrency (multiplicative decrease)
      - rate <= TIMEOUT_THRESHOLD → add one thread back (additive increase)

    Leave adapt_concurrency=False (default) when timeouts are expected by
    design (e.g. ICMP subnet scans, TCP scans on filtered hosts) — in those
    cases AIMD mistakes "host not there" for network congestion and kills
    throughput.
    """

    def __init__(self, max_threads: int, timeout: float, adapt_concurrency: bool = False) -> None:
        self.timeout = timeout
        self._max = max_threads
        self._adapt_concurrency = adapt_concurrency
        self._sem = _AdaptiveSemaphore(initial=max_threads, maximum=max_threads)
        self._lock = threading.Lock()
        self._timeouts = 0
        self._total = 0
        self._rtts: list[float] = []

    def acquire(self) -> None:
        self._sem.acquire()

    def release(self) -> None:
        self._sem.release()

    def record(self, is_timeout: bool, rtt: float | None = None) -> None:
        """Record the outcome of one probe; adapts when the window is full."""
        with self._lock:
            self._total += 1
            if is_timeout:
                self._timeouts += 1
            elif rtt is not None:
                self._rtts.append(rtt)
                if len(self._rtts) == 1:
                    self._update_timeout()
            if self._total >= _WINDOW_SIZE:
                self._adapt()

    def _update_timeout(self) -> None:
        if self._rtts:
            avg_rtt = sum(self._rtts) / len(self._rtts)
            self.timeout = max(_MIN_TIMEOUT, avg_rtt * _RTT_MULTIPLIER)

    def _adapt(self) -> None:
        old_limit = self._sem.limit

        if self._adapt_concurrency:
            timeout_rate = self._timeouts / self._total
            if timeout_rate > _TIMEOUT_THRESHOLD:
                new_limit = max(1, old_limit // 2)
            else:
                new_limit = min(self._max, old_limit + 1)

            if new_limit != old_limit:
                self._sem.set_limit(new_limit)

        self._update_timeout()

        self._timeouts = 0
        self._total = 0
        self._rtts.clear()

    @property
    def concurrency(self) -> int:
        return self._sem.limit
