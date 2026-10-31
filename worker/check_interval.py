"""Interval gate for scheduled GitHub Actions runs.

The workflow fires every hour; this script decides whether enough time has
passed since proxies.txt last changed in git history. Manual runs
(Workflow dispatch) set FORCE_UPDATE=1 and always proceed.

Usage:  python -m worker.check_interval
Behaviour:
  - prints a human-readable decision
  - writes ``should_run=true|false`` to $GITHUB_OUTPUT when available
  - always exits 0
"""
from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

from .config import load_config


def _last_update_epoch(root: Path, proxies_file: str) -> int | None:
    """Epoch of the last commit touching proxies.txt (None if never)."""
    try:
        proc = subprocess.run(
            ["git", "log", "-1", "--format=%ct", "--", proxies_file],
            capture_output=True,
            text=True,
            cwd=str(root),
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = (proc.stdout or "").strip()
    if proc.returncode != 0 or not value.isdigit():
        return None
    return int(value)


def main() -> None:
    root = Path.cwd()
    config = load_config(root)

    forced = os.environ.get("FORCE_UPDATE", "").strip().lower() in ("1", "true", "yes")
    interval_s = config.update_interval_hours * 3600
    last = _last_update_epoch(root, config.proxies_file)

    if forced:
        should_run, reason = True, "manual dispatch (FORCE_UPDATE) -> always run"
    elif last is None:
        should_run, reason = True, "no previous update found -> run"
    else:
        elapsed = time.time() - last
        should_run = elapsed >= interval_s
        remaining = max(0, interval_s - elapsed)
        reason = (
            f"last update {elapsed / 3600:.2f}h ago, interval "
            f"{config.update_interval_hours}h -> "
            + ("run" if should_run else f"skip (next run in {remaining / 3600:.2f}h)")
        )

    print(("RUN" if should_run else "SKIP") + ": " + reason)

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        try:
            with open(github_output, "a", encoding="utf-8") as fh:
                fh.write(f"should_run={'true' if should_run else 'false'}\n")
        except OSError as exc:
            print(f"warning: cannot write GITHUB_OUTPUT: {exc}")


if __name__ == "__main__":
    main()
