"""Central configuration for the proxy pool worker.

Every tunable lives in ``config.json`` at the repository root. Values are
merged over safe defaults here so a missing key never crashes a run, and
nothing operational is hard-coded in the rest of the source code.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULTS: dict[str, Any] = {
    # --- Automation -----------------------------------------------------
    # How often the pool is refreshed (hours). The GitHub Actions workflow
    # wakes up every hour and only performs real work once this much time
    # has passed since the last update (see worker/check_interval.py).
    "update_interval_hours": 6,
    # --- Connectivity testing ------------------------------------------
    # Timeout (seconds) for the single HTTP request made *through* each
    # proxy during the connectivity test.
    "connectivity_timeout_seconds": 10,
    # Extra attempts granted to configurations that already existed in
    # proxies.txt. New configs NEVER get retries (see worker/tester.py).
    "old_config_retries": 3,
    # Small HTTP(S) endpoint requested through every proxy.
    "test_url": "https://www.gstatic.com/generate_204",
    # Parallel test workers.
    "test_workers": 16,
    # --- Proxy core -----------------------------------------------------
    # sing-box release used for the real protocol-level connectivity tests.
    "sing_box_version": "1.10.7",
    # Binary name/path; the workflow overrides this via SING_BOX_PATH.
    "sing_box_path": "sing-box",
    # How long to wait for the core to open its local SOCKS port.
    "sing_box_startup_timeout_seconds": 5,
    # --- Fetching -------------------------------------------------------
    "fetch_timeout_seconds": 30,
    "fetch_user_agent": "Mozilla/5.0 (compatible; proxy-pool-worker/1.1)",
    "max_download_bytes": 8 * 1024 * 1024,
    # --- Local test port pool -------------------------------------------
    "port_pool_base": 44100,
    # --- Files -----------------------------------------------------------
    "subscriptions_file": "subscriptions.txt",
    "proxies_file": "proxies.txt",
}


@dataclass(frozen=True)
class Config:
    update_interval_hours: int
    old_config_retries: int
    connectivity_timeout_seconds: int
    test_url: str
    test_workers: int
    sing_box_version: str
    sing_box_path: str
    sing_box_startup_timeout_seconds: int
    fetch_timeout_seconds: int
    fetch_user_agent: str
    max_download_bytes: int
    port_pool_base: int
    subscriptions_file: str
    proxies_file: str
    root: Path


def _as_int(value: Any, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def load_config(root: Path | None = None) -> Config:
    """Load config.json (if present) merged over DEFAULTS."""
    root = (root or Path.cwd()).resolve()
    raw: dict[str, Any] = dict(DEFAULTS)

    path = root / "config.json"
    if path.is_file():
        try:
            user = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"[config] config.json is not valid JSON: {exc}")
        if isinstance(user, dict):
            raw.update({k: v for k, v in user.items() if k in DEFAULTS})

    return Config(
        update_interval_hours=max(1, _as_int(raw["update_interval_hours"], 6)),
        old_config_retries=max(0, _as_int(raw["old_config_retries"], 3)),
        connectivity_timeout_seconds=max(2, _as_int(raw["connectivity_timeout_seconds"], 10)),
        test_url=str(raw["test_url"]).strip(),
        test_workers=min(64, max(1, _as_int(raw["test_workers"], 16))),
        sing_box_version=str(raw["sing_box_version"]).strip(),
        # The workflow sets SING_BOX_PATH to whatever binary it downloaded.
        sing_box_path=os.environ.get("SING_BOX_PATH", "").strip()
        or str(raw["sing_box_path"]).strip(),
        sing_box_startup_timeout_seconds=max(
            1, _as_int(raw["sing_box_startup_timeout_seconds"], 5)
        ),
        fetch_timeout_seconds=max(5, _as_int(raw["fetch_timeout_seconds"], 30)),
        fetch_user_agent=str(raw["fetch_user_agent"]).strip()
        or "proxy-pool-worker",
        max_download_bytes=max(65536, _as_int(raw["max_download_bytes"], 8 * 1024 * 1024)),
        port_pool_base=max(1024, min(60000, _as_int(raw["port_pool_base"], 44100))),
        subscriptions_file=str(raw["subscriptions_file"]).strip() or "subscriptions.txt",
        proxies_file=str(raw["proxies_file"]).strip() or "proxies.txt",
        root=root,
    )
