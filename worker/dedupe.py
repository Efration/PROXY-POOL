"""Deduplication.

The rule is intentionally simple and is used for BOTH deduplication passes:

    key = host/IP + port        (nothing else -- ever)

Two URIs that resolve to the same ``endpoint`` are duplicates regardless of
protocol, UUID, password, SNI, TLS settings, or any other field.
"""
from __future__ import annotations

from typing import Iterable

from .parser import ProxyConfig


def dedupe_by_endpoint(
    configs: Iterable[ProxyConfig],
) -> tuple[list[ProxyConfig], int]:
    """Keep the first config for every unique ``host:port`` endpoint.

    Returns ``(kept, dropped_count)`` preserving input order.
    """
    seen: set[str] = set()
    kept: list[ProxyConfig] = []
    dropped = 0
    for cfg in configs:
        key = cfg.endpoint
        if key in seen:
            dropped += 1
            continue
        seen.add(key)
        kept.append(cfg)
    return kept, dropped
