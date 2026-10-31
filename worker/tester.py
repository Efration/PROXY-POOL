"""Concurrency + THE retry policy.

Retry rule (mandatory, do not blur):

* EXISTING configuration (endpoint was already present in proxies.txt
  before this update):
      initial test -> FAIL -> retry up to ``old_retries`` times.
      -> any success keeps the config; all attempts failing removes it.
* NEW configuration (endpoint first seen during this update):
      EXACTLY ONE test. No retries. Success keeps it, failure discards it.

A new download whose endpoint matches an old entry is classified as EXISTING
(via the endpoint key) and the original old line is retained -- so retries
are only ever granted to endpoints the pool already contained.
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Protocol

from .parser import ProxyConfig
from .singbox import CoreResult


@dataclass
class Candidate:
    cfg: ProxyConfig
    is_old: bool  # True == endpoint existed in proxies.txt before this run


@dataclass
class Outcome:
    cfg: ProxyConfig
    is_old: bool
    ok: bool
    attempts: int
    detail: str
    elapsed_ms: float = 0.0


@dataclass(frozen=True)
class ScanProgress:
    """Live snapshot of a running connectivity-test pool.

    ``extracted`` is the raw count produced by the finished extraction phase
    (0 when the tester does not know it, e.g. a shard that only received a
    pre-built candidate file). ``assigned`` is how many of those configs this
    process is actually testing.
    """

    extracted: int
    assigned: int
    tested: int
    healthy: int
    failed: int
    waiting: int
    active_workers: int
    total_workers: int
    idle_workers: int
    completed_workers: int

    @property
    def remaining(self) -> int:
        return self.waiting + self.active_workers


class SingleShotTester(Protocol):
    def test_once(self, cfg: ProxyConfig, listen_port: int) -> CoreResult: ...


class PortPool:
    """Hands out distinct local listen ports to concurrent test workers."""

    def __init__(self, base: int, count: int) -> None:
        self._ports = [base + i for i in range(max(1, count))]
        self._lock = threading.Lock()
        self._next = 0

    def acquire(self) -> int:
        with self._lock:
            port = self._ports[self._next % len(self._ports)]
            self._next += 1
            return port


def allowed_attempts(is_old: bool, old_retries: int) -> int:
    """The entire retry contract in one place.

    Existing configs: 1 initial test + ``old_retries`` additional attempts.
    New configs:      exactly 1 test. NEVER retries.
    """
    return (1 + max(0, old_retries)) if is_old else 1


def test_candidate(
    candidate: Candidate,
    tester: SingleShotTester,
    old_retries: int,
    port: int,
) -> Outcome:
    cfg = candidate.cfg
    attempts_left = allowed_attempts(candidate.is_old, old_retries)
    last: CoreResult | None = None
    attempts = 0

    while attempts_left > 0:
        attempts += 1
        attempts_left -= 1
        last = tester.test_once(cfg, port)
        if last.ok:
            return Outcome(
                cfg=cfg,
                is_old=candidate.is_old,
                ok=True,
                attempts=attempts,
                detail=last.detail,
                elapsed_ms=last.elapsed_ms,
            )

    assert last is not None  # loop always runs at least once
    return Outcome(
        cfg=cfg,
        is_old=candidate.is_old,
        ok=False,
        attempts=attempts,
        detail=last.detail,
        elapsed_ms=last.elapsed_ms,
    )


def run_tests(
    candidates: list[Candidate],
    tester: SingleShotTester,
    old_retries: int,
    workers: int,
    port_base: int,
    progress: Callable[[ScanProgress], None] | None = None,
    verbose: Callable[[Outcome], None] | None = None,
    extracted: int = 0,
) -> list[Outcome]:
    """Test every candidate concurrently, honouring the retry policy.

    Testing workers are started only after ``candidates`` is already complete:
    this function never fetches or parses subscriptions.

    ``progress`` is invoked at the start of the scan, after every completed
    test (throttled to keep logs readable), and once more when the scan
    finishes. ``verbose`` (if given) is invoked for every finished outcome.
    """
    total_workers = max(1, workers)
    total = len(candidates)
    assigned = total
    extracted_n = extracted if extracted > 0 else assigned

    def snapshot(tested: int, healthy: int, failed: int, active: int) -> ScanProgress:
        waiting = max(0, assigned - tested - active)
        idle = max(0, total_workers - active)
        # A worker is "completed" once the queue is empty and that slot is idle.
        completed = idle if waiting == 0 else 0
        if tested >= assigned:
            completed = total_workers
            idle = total_workers
            active = 0
            waiting = 0
        return ScanProgress(
            extracted=extracted_n,
            assigned=assigned,
            tested=tested,
            healthy=healthy,
            failed=failed,
            waiting=waiting,
            active_workers=active,
            total_workers=total_workers,
            idle_workers=idle,
            completed_workers=completed,
        )

    if not candidates:
        if progress is not None:
            progress(snapshot(0, 0, 0, 0))
        return []

    pool = PortPool(base=port_base, count=total_workers)
    outcomes_by_index: dict[int, Outcome] = {}
    state = {"done": 0, "ok": 0, "fail": 0, "active": 0}
    lock = threading.Lock()
    last_emit = [0.0]
    min_interval = 2.0
    every_n = 5

    def emit(force: bool = False) -> None:
        if progress is None:
            return
        now = time.monotonic()
        done = state["done"]
        if not (
            force
            or done == 0
            or done == 1
            or done == total
            or done % every_n == 0
            or (now - last_emit[0]) >= min_interval
        ):
            return
        last_emit[0] = now
        progress(
            snapshot(state["done"], state["ok"], state["fail"], state["active"])
        )

    def work(item: tuple[int, Candidate]) -> tuple[int, Outcome]:
        index, candidate = item
        with lock:
            state["active"] += 1
        try:
            port = pool.acquire()
            try:
                outcome = test_candidate(candidate, tester, old_retries, port)
            except Exception as exc:  # belt & braces: never lose the whole pool
                outcome = Outcome(
                    cfg=candidate.cfg,
                    is_old=candidate.is_old,
                    ok=False,
                    attempts=0,
                    detail=f"test harness error: {exc}",
                )
            return index, outcome
        finally:
            with lock:
                state["active"] -= 1

    with ThreadPoolExecutor(max_workers=total_workers) as executor:
        emit(force=True)
        futures = {
            executor.submit(work, item): item[0]
            for item in enumerate(candidates)
        }
        for fut in as_completed(futures):
            index, outcome = fut.result()
            outcomes_by_index[index] = outcome
            with lock:
                state["done"] += 1
                state["ok" if outcome.ok else "fail"] += 1
                if verbose is not None:
                    verbose(outcome)
                emit()
        emit(force=True)

    return [outcomes_by_index[i] for i in range(total)]
