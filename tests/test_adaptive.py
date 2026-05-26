import threading
from sondare.utils.adaptive_pool import _AdaptiveSemaphore, AdaptivePool, _WINDOW_SIZE


class TestAdaptiveSemaphore:
    def test_acquire_and_release(self):
        sem = _AdaptiveSemaphore(initial=2, maximum=2)
        sem.acquire()
        sem.acquire()
        assert sem._active == 2
        sem.release()
        assert sem._active == 1

    def test_blocks_at_limit(self):
        sem = _AdaptiveSemaphore(initial=1, maximum=2)
        sem.acquire()
        unblocked = threading.Event()

        def try_acquire():
            sem.acquire()
            unblocked.set()

        t = threading.Thread(target=try_acquire, daemon=True)
        t.start()
        assert not unblocked.wait(timeout=0.05)
        sem.release()
        assert unblocked.wait(timeout=1.0)

    def test_set_limit_increases_allows_more(self):
        sem = _AdaptiveSemaphore(initial=1, maximum=4)
        sem.acquire()
        unblocked = threading.Event()

        def try_acquire():
            sem.acquire()
            unblocked.set()

        t = threading.Thread(target=try_acquire, daemon=True)
        t.start()
        sem.set_limit(2)
        assert unblocked.wait(timeout=1.0)

    def test_set_limit_clamped_to_max(self):
        sem = _AdaptiveSemaphore(initial=2, maximum=3)
        sem.set_limit(10)
        assert sem.limit == 3

    def test_set_limit_clamped_to_one(self):
        sem = _AdaptiveSemaphore(initial=2, maximum=2)
        sem.set_limit(0)
        assert sem.limit == 1


class TestAdaptivePool:
    def test_initial_concurrency_equals_max(self):
        pool = AdaptivePool(max_threads=10, timeout=3.0)
        assert pool.concurrency == 10

    def test_initial_timeout(self):
        pool = AdaptivePool(max_threads=5, timeout=2.5)
        assert pool.timeout == 2.5

    def test_adapt_concurrency_off_by_default(self):
        pool = AdaptivePool(max_threads=20, timeout=3.0)
        assert pool._adapt_concurrency is False

    def test_concurrency_unchanged_when_adapt_concurrency_off(self):
        pool = AdaptivePool(max_threads=20, timeout=3.0, adapt_concurrency=False)
        for _ in range(_WINDOW_SIZE):
            pool.record(is_timeout=True)
        assert pool.concurrency == 20  # not reduced despite all timeouts

    def test_high_timeout_rate_halves_concurrency_when_enabled(self):
        pool = AdaptivePool(max_threads=20, timeout=3.0, adapt_concurrency=True)
        for _ in range(_WINDOW_SIZE):
            pool.record(is_timeout=True)
        assert pool.concurrency == 10

    def test_low_timeout_rate_adds_one_thread_when_enabled(self):
        pool = AdaptivePool(max_threads=10, timeout=3.0, adapt_concurrency=True)
        pool._sem.set_limit(8)
        for _ in range(_WINDOW_SIZE):
            pool.record(is_timeout=False, rtt=0.1)
        assert pool.concurrency == 9

    def test_concurrency_does_not_exceed_max_when_enabled(self):
        pool = AdaptivePool(max_threads=5, timeout=3.0, adapt_concurrency=True)
        for _ in range(_WINDOW_SIZE):
            pool.record(is_timeout=False, rtt=0.1)
        assert pool.concurrency == 5

    def test_rtt_updates_timeout(self):
        pool = AdaptivePool(max_threads=5, timeout=10.0)
        for _ in range(_WINDOW_SIZE):
            pool.record(is_timeout=False, rtt=1.0)  # avg=1.0, new=2.5
        assert abs(pool.timeout - 2.5) < 1e-9

    def test_timeout_not_below_minimum(self):
        pool = AdaptivePool(max_threads=5, timeout=10.0)
        for _ in range(_WINDOW_SIZE):
            pool.record(is_timeout=False, rtt=0.01)  # avg=0.01, new=0.025 < 0.5
        assert pool.timeout == 0.5

    def test_rtt_updates_timeout_regardless_of_adapt_concurrency(self):
        pool = AdaptivePool(max_threads=5, timeout=10.0, adapt_concurrency=False)
        for _ in range(_WINDOW_SIZE):
            pool.record(is_timeout=False, rtt=1.0)
        assert abs(pool.timeout - 2.5) < 1e-9

    def test_window_resets_after_adapt(self):
        pool = AdaptivePool(max_threads=10, timeout=3.0)
        for _ in range(_WINDOW_SIZE):
            pool.record(is_timeout=True)
        assert pool._total == 0
        assert pool._timeouts == 0

    def test_adapt_only_triggers_at_window_boundary(self):
        pool = AdaptivePool(max_threads=20, timeout=3.0, adapt_concurrency=True)
        for _ in range(_WINDOW_SIZE - 1):
            pool.record(is_timeout=True)
        assert pool.concurrency == 20
        pool.record(is_timeout=True)
        assert pool.concurrency == 10

    def test_acquire_release_delegates_to_semaphore(self):
        pool = AdaptivePool(max_threads=2, timeout=1.0)
        pool.acquire()
        assert pool._sem._active == 1
        pool.release()
        assert pool._sem._active == 0
