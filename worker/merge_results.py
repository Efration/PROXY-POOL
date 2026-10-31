"""Merge shard outcomes and write final proxies.txt."""
from __future__ import annotations

import json
import logging
import sys
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path

from .config import Config, load_config
from .parser import ProxyConfig, parse_uri

log = logging.getLogger("pool-merge")


@dataclass
class Outcome:
    cfg: ProxyConfig
    is_old: bool
    ok: bool
    attempts: int
    detail: str
    elapsed_ms: float = 0.0


def load_existing(path: Path) -> "OrderedDict[str, ProxyConfig]":
    existing: "OrderedDict[str, ProxyConfig]" = OrderedDict()
    if not path.is_file():
        return existing
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        cfg = parse_uri(line)
        if cfg is not None:
            existing.setdefault(cfg.endpoint, cfg)
    return existing


def write_output(path: Path, kept: list[ProxyConfig]) -> bool:
    content = "".join(cfg.raw.strip() + "\n" for cfg in kept)
    previous = ""
    if path.is_file():
        previous = path.read_text(encoding="utf-8", errors="replace")
    if previous == content:
        return False
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)
    return True


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="merge shard outcomes")
    parser.add_argument(
        "--root",
        default=".",
        help="repository root containing config.json (default: cwd)",
    )
    parser.add_argument(
        "--total-shards",
        type=int,
        required=True,
        help="total number of shards to merge",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )

    config = load_config(Path(args.root))
    total_shards = args.total_shards

    # Load all partial outcomes
    all_outcomes: list[Outcome] = []
    for shard in range(total_shards):
        part_file = config.root / f"outcomes.part{shard}.json"
        if not part_file.is_file():
            log.error("missing %s", part_file.name)
            return 1
        data = json.loads(part_file.read_text(encoding="utf-8"))
        for d in data:
            cfg = parse_uri(d["cfg"]["raw"])
            if cfg is None:
                continue
            all_outcomes.append(
                Outcome(
                    cfg=cfg,
                    is_old=d["is_old"],
                    ok=d["ok"],
                    attempts=d["attempts"],
                    detail=d["detail"],
                    elapsed_ms=d.get("elapsed_ms", 0.0),
                )
            )
        log.info("loaded %d outcomes from %s", len(data), part_file.name)
        # Clean up
        part_file.unlink(missing_ok=True)

    log.info("total outcomes merged: %d", len(all_outcomes))

    # Final classification & output
    kept_old = [o for o in all_outcomes if o.ok and o.is_old]
    kept_new = [o for o in all_outcomes if o.ok and not o.is_old]
    removed_old = [o for o in all_outcomes if not o.ok and o.is_old]
    dropped_new = [o for o in all_outcomes if not o.ok and not o.is_old]

    for o in removed_old:
        log.info(
            "  DROP OLD %s - failed %d attempt(s): %s",
            o.cfg,
            o.attempts,
            o.detail,
        )
    retry_saved = sum(1 for o in kept_old if o.attempts > 1)
    if retry_saved:
        log.info(
            "  %d existing config(s) survived thanks to a retry", retry_saved
        )

    kept = [o.cfg for o in all_outcomes if o.ok]
    changed = write_output(config.root / config.proxies_file, kept)

    log.info("=" * 64)
    log.info(
        "summary: existing %d kept / %d removed | new %d kept / %d discarded",
        len(kept_old),
        len(removed_old),
        len(kept_new),
        len(dropped_new),
    )
    log.info(
        "proxies.txt: %d healthy config(s) written (%s)",
        len(kept),
        "changed" if changed else "no change",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())