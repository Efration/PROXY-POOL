"""Main pipeline - the exact workflow of the worker:

    subscriptions.txt
        -> fetch ALL subscription URLs             (errors are isolated)
        -> decode Base64 when necessary
        -> convert sing-box configs to proxy URIs
        -> extract ALL proxy configurations
        -> FINISH the complete extraction phase    (no testers running yet)
        -> dedupe NEW configurations               (host/IP + port)
        -> load existing proxies.txt
        -> combine OLD + NEW
        -> dedupe again                            (host/IP + port)
        -> identify OLD vs NEW                     (endpoint membership)
        -> ONLY THEN divide the list among workers
        -> connectivity test every candidate
              OLD: initial test + up to N retries
              NEW: exactly ONE test, never retried
        -> write healthy OLD + NEW back to proxies.txt

Usage:  python -m worker.main [--verbose]
"""
from __future__ import annotations

import argparse
import logging
import shutil
import sys
from collections import OrderedDict
from pathlib import Path

from .config import Config, load_config
from .dedupe import dedupe_by_endpoint
from .fetcher import fetch_subscription
from .parser import ProxyConfig, parse_text, parse_uri
from .singbox import CoreTester, find_core, preflight
from .provider import provider_from_url, prefix_config_name
from .subscription import normalize_subscription
from .tester import Candidate, Outcome, ScanProgress, run_tests

log = logging.getLogger("pool-worker")


# ---------------------------------------------------------------------------
# IO helpers
# ---------------------------------------------------------------------------


def read_subscription_urls(path: Path) -> list[str]:
    if not path.is_file():
        log.warning("%s not found - no subscriptions will be fetched", path.name)
        return []
    urls: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            urls.append(line)
    return urls


def load_existing(path: Path) -> "OrderedDict[str, ProxyConfig]":
    """Parse proxies.txt into an ordered {endpoint: config} map."""
    existing: "OrderedDict[str, ProxyConfig]" = OrderedDict()
    if not path.is_file():
        log.info("%s does not exist yet - starting with an empty pool", path.name)
        return existing
    bad = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        cfg = parse_uri(line)
        if cfg is None:
            bad += 1
            continue
        existing.setdefault(cfg.endpoint, cfg)  # first occurrence wins
    if bad:
        log.warning("dropped %d unparseable line(s) from %s", bad, path.name)
    return existing


def write_output(path: Path, kept: list[ProxyConfig]) -> bool:
    """Atomically write proxies.txt. Returns True when content changed."""
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


# ---------------------------------------------------------------------------
# Pipeline stages
# ---------------------------------------------------------------------------


def fetch_and_extract(config: Config) -> list[ProxyConfig]:
    """Fetch every subscription and extract every config. Does NOT test.

    Workers for connectivity testing are not created here. The full
    extraction phase must finish before the resulting list is divided.
    """
    urls = read_subscription_urls(config.root / config.subscriptions_file)
    if not urls:
        return []
    log.info(
        "stage 1-3: fetching ALL %d subscription URL(s) and extracting ALL "
        "configs (testing workers are NOT started yet)",
        len(urls),
    )

    collected: list[ProxyConfig] = []
    ok_sources = 0
    kinds = {"uri": 0, "sing-box": 0}
    for url in urls:
        result = fetch_subscription(
            url,
            timeout_seconds=config.fetch_timeout_seconds,
            user_agent=config.fetch_user_agent,
            max_bytes=config.max_download_bytes,
        )
        if not result.ok:
            log.warning("  source FAILED - %s (%s)", url, result.error)
            continue
        normalized, kind = normalize_subscription(result.text)
        configs = parse_text(normalized)
        provider = provider_from_url(url)
        if provider:
            for cfg in configs:
                cfg.raw = prefix_config_name(cfg.raw, provider)
        kinds[kind] = kinds.get(kind, 0) + 1
        untestable = sum(1 for c in configs if not c.testable)
        ok_sources += 1
        log.info(
            "  source OK (%d bytes, %s, provider=%s) -> %d config(s)%s - %s",
            len(result.text),
            kind,
            provider or "-",
            len(configs),
            f" [{untestable} untestable, kept for dedupe]" if untestable else "",
            url,
        )
        collected.extend(configs)

    log.info(
        "extraction phase complete: fetched %d/%d source(s) "
        "(%d uri / %d sing-box); extracted %d raw config(s). "
        "Testing workers will be divided only after this point.",
        ok_sources,
        len(urls),
        kinds.get("uri", 0),
        kinds.get("sing-box", 0),
        len(collected),
    )
    return collected


def merge_and_classify(
    existing: "OrderedDict[str, ProxyConfig]", new_configs: list[ProxyConfig]
) -> list[Candidate]:
    """Dedupe #2 + OLD/NEW classification, strictly by endpoint membership."""
    candidates: list[Candidate] = []
    for cfg in existing.values():
        candidates.append(Candidate(cfg=cfg, is_old=True))

    dropped_as_existing = 0
    for cfg in new_configs:
        if cfg.endpoint in existing:
            # Same host/IP + port as an existing entry: it IS an existing
            # endpoint. The original old line wins; the new duplicate is NOT
            # treated as a new configuration.
            dropped_as_existing += 1
            continue
        candidates.append(Candidate(cfg=cfg, is_old=False))

    old_n = sum(1 for c in candidates if c.is_old)
    new_n = len(candidates) - old_n
    log.info(
        "combined pool: %d existing + %d genuinely new "
        "(%d new download(s) dropped because their endpoint already exists)",
        old_n,
        new_n,
        dropped_as_existing,
    )
    return candidates


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="proxy pool updater")
    parser.add_argument(
        "--verbose", action="store_true", help="log every connectivity result"
    )
    parser.add_argument(
        "--root",
        default=".",
        help="repository root containing config.json (default: cwd)",
    )
    parser.add_argument(
        "--shard",
        type=int,
        default=0,
        help="shard index (0-based) for distributed testing",
    )
    parser.add_argument(
        "--total-shards",
        type=int,
        default=1,
        help="total number of shards",
    )
    parser.add_argument(
        "--candidates-file",
        type=str,
        help="path to candidates.json (skips fetch/parse/dedupe/classify)",
    )
    parser.add_argument(
        "--save-candidates",
        type=str,
        help="save candidates to file and exit (for prepare stage)",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )
    config = load_config(Path(args.root))
    log.info(
        "config: interval=%dh retries(old only)=%d timeout=%ds workers=%d url=%s",
        config.update_interval_hours,
        config.old_config_retries,
        config.connectivity_timeout_seconds,
        config.test_workers,
        config.test_url,
    )

    core_path = find_core(config.sing_box_path, config.root)
    if core_path is None:
        log.error(
            "sing-box binary not found (hint: SING_BOX_PATH / config sing_box_path "
            "/ tools/sing-box). Refusing to run without a test core."
        )
        return 2
    log.info("core: %s -> %s", core_path, preflight(core_path))
    if shutil.which("curl") is None:
        log.error("curl is required for connectivity probes but was not found")
        return 2

    # -- Load or build candidates. Extraction ALWAYS finishes before testing. --
    extracted_count = 0
    if args.candidates_file:
        log.info(
            "loading pre-extracted candidates from %s "
            "(extraction already finished in the prepare stage)",
            args.candidates_file,
        )
        import json
        payload = json.loads(Path(args.candidates_file).read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            extracted_count = int(payload.get("extracted") or 0)
            rows = payload.get("candidates") or []
        else:
            rows = payload
        candidates = []
        for d in rows:
            cfg = parse_uri(d["raw"])
            if cfg is None:
                continue
            candidates.append(Candidate(cfg=cfg, is_old=d["is_old"]))
        if extracted_count <= 0:
            extracted_count = len(candidates)
        log.info(
            "loaded %d candidates (extracted=%d). "
            "Fetch/decode/extract will NOT run in this process.",
            len(candidates),
            extracted_count,
        )
    else:
        # -- stages 1-3: fetch ALL + decode + extract ALL ----------------------
        collected = fetch_and_extract(config)
        extracted_count = len(collected)

        # -- stage 4: dedupe the freshly downloaded configs --------------------
        fresh, dropped_fresh = dedupe_by_endpoint(collected)
        log.info(
            "stage 4: dedupe fresh configs by host:port -> %d kept, %d duplicate(s) dropped",
            len(fresh),
            dropped_fresh,
        )

        # -- stages 5-6: load existing + second dedupe + classification --------
        existing = load_existing(config.root / config.proxies_file)
        log.info("stage 5: loaded %d existing config(s)", len(existing))
        candidates = merge_and_classify(existing, fresh)
        log.info(
            "extraction + classify complete: extracted=%d, assigned for testing=%d. "
            "Only now will the list be divided among workers.",
            extracted_count,
            len(candidates),
        )

    # Save candidates and exit (prepare mode) — testing workers are not started.
    if args.save_candidates:
        import json
        data = {
            "extracted": extracted_count,
            "candidates": [
                {
                    "raw": c.cfg.raw,
                    "is_old": c.is_old,
                    "endpoint": c.cfg.endpoint,
                    "scheme": c.cfg.scheme,
                }
                for c in candidates
            ],
        }
        Path(args.save_candidates).write_text(json.dumps(data), encoding="utf-8")
        log.info(
            "saved %d candidates (extracted=%d) to %s — extraction finished, "
            "testing will start in later jobs/workers",
            len(candidates),
            extracted_count,
            args.save_candidates,
        )
        return 0

    # -- stages 7-9: divide the COMPLETE list, then test ----------------------
    tester = CoreTester(
        core_path=core_path,
        test_url=config.test_url,
        timeout_seconds=config.connectivity_timeout_seconds,
        startup_timeout_seconds=config.sing_box_startup_timeout_seconds,
    )

    def on_progress(p: ScanProgress) -> None:
        log.info(
            "scan: extracted=%d assigned=%d tested=%d/%d healthy=%d failed=%d "
            "waiting=%d | workers: active=%d/%d idle=%d completed=%d",
            p.extracted,
            p.assigned,
            p.tested,
            p.assigned,
            p.healthy,
            p.failed,
            p.waiting,
            p.active_workers,
            p.total_workers,
            p.idle_workers,
            p.completed_workers,
        )

    def on_verbose(outcome: Outcome) -> None:
        kind = "OLD" if outcome.is_old else "NEW"
        state = "KEEP " if outcome.ok else "DROP "
        log.info(
            "  %s%s %-4s %-48s attempt(s)=%d %s",
            state,
            kind,
            outcome.cfg.scheme,
            str(outcome.cfg),
            outcome.attempts,
            outcome.detail,
        )

    # Shard only after the complete extracted list exists.
    full_list_size = len(candidates)
    if args.total_shards > 1:
        shard_size = (full_list_size + args.total_shards - 1) // args.total_shards
        start = args.shard * shard_size
        end = min(start + shard_size, full_list_size)
        candidates = candidates[start:end]
        log.info(
            "stage 7: extraction finished; dividing %d configs among %d shards "
            "-> this worker is shard %d/%d with %d assigned (indices %d-%d)",
            full_list_size,
            args.total_shards,
            args.shard,
            args.total_shards - 1,
            len(candidates),
            start,
            end - 1 if end else 0,
        )
    else:
        log.info(
            "stage 7: extraction finished; dividing %d configs among %d "
            "in-process test workers",
            full_list_size,
            config.test_workers,
        )

    log.info(
        "stage 8: starting proxy tests: extracted=%d assigned=%d workers=%d",
        extracted_count,
        len(candidates),
        config.test_workers,
    )
    outcomes = run_tests(
        candidates,
        tester,
        old_retries=config.old_config_retries,
        workers=config.test_workers,
        port_base=config.port_pool_base + args.shard * 100,  # avoid port collisions
        progress=on_progress,
        verbose=on_verbose if args.verbose else None,
        extracted=extracted_count,
    )

    # -- stage 10: save partial outcomes for merging ---------------------------
    if args.total_shards > 1:
        import json
        from dataclasses import asdict

        out_file = config.root / f"outcomes.part{args.shard}.json"
        data = [asdict(o) for o in outcomes]
        out_file.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        log.info("saved partial outcomes to %s", out_file.name)
        return 0

    # -- stage 10: final output (single-shard mode) ----------------------------
    kept_old = [o for o in outcomes if o.ok and o.is_old]
    kept_new = [o for o in outcomes if o.ok and not o.is_old]
    removed_old = [o for o in outcomes if not o.ok and o.is_old]
    dropped_new = [o for o in outcomes if not o.ok and not o.is_old]

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

    kept = [o.cfg for o in outcomes if o.ok]
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
