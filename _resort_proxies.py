#!/usr/bin/env python3
"""Sort proxy URIs by country tag and renumber sequentially within each country."""
from __future__ import annotations

import base64
import json
import re
import sys
import urllib.parse
from collections import defaultdict

TAG_RE = re.compile(r"\[([A-Z]{2})(\d+)\]")


def b64decode_padded(data: str) -> bytes:
    s = data.strip()
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s)


def extract_tag(uri: str) -> tuple[str, int] | None:
    if uri.startswith("vmess://"):
        payload = uri[8:]
        raw = b64decode_padded(payload).decode("utf-8")
        m = TAG_RE.search(raw)
        if m:
            return m.group(1), int(m.group(2))
        try:
            obj = json.loads(raw)
            ps = str(obj.get("ps", ""))
            m = TAG_RE.search(ps)
            if m:
                return m.group(1), int(m.group(2))
        except json.JSONDecodeError:
            return None
        return None

    if "#" not in uri:
        return None
    frag = urllib.parse.unquote(uri.split("#", 1)[1])
    m = TAG_RE.search(frag)
    if not m:
        return None
    return m.group(1), int(m.group(2))


def retag(uri: str, cc: str, new_num: int) -> str:
    new_tag = f"[{cc}{new_num}]"
    if uri.startswith("vmess://"):
        payload = uri[8:]
        raw = b64decode_padded(payload).decode("utf-8")
        m = TAG_RE.search(raw)
        if not m:
            raise ValueError(f"no tag in vmess payload: {uri[:80]}")
        raw2 = raw[: m.start()] + new_tag + raw[m.end() :]
        encoded = base64.b64encode(raw2.encode("utf-8")).decode("ascii")
        return "vmess://" + encoded

    if "#" not in uri:
        raise ValueError(f"no fragment: {uri[:80]}")
    body, frag = uri.split("#", 1)
    frag_decoded = urllib.parse.unquote(frag)
    m = TAG_RE.search(frag_decoded)
    if not m:
        raise ValueError(f"no tag in fragment: {uri[:80]}")
    # Keep emoji URL-encoded; only the [CCn] suffix is plain in the source list.
    frag_new = frag_decoded[: m.start()] + new_tag + frag_decoded[m.end() :]
    # Re-encode everything except the [CCn] tag so the output matches the input style.
    prefix = frag_new[: m.start()]
    suffix = frag_new[m.start() :]
    encoded_prefix = urllib.parse.quote(prefix, safe="")
    return f"{body}#{encoded_prefix}{suffix}"


def main() -> int:
    path = sys.argv[1]
    text = open(path, "r", encoding="utf-8").read()
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]

    parsed: list[tuple[str, int, str]] = []
    for uri in lines:
        tag = extract_tag(uri)
        if tag is None:
            print(f"FAILED TO PARSE: {uri[:120]}", file=sys.stderr)
            return 1
        parsed.append((tag[0], tag[1], uri))

    parsed.sort(key=lambda x: (x[0], x[1], x[2]))

    grouped: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for cc, num, uri in parsed:
        grouped[cc].append((num, uri))

    out_lines: list[str] = []
    mapping: list[str] = []
    for cc in sorted(grouped):
        items = grouped[cc]
        for i, (old_num, uri) in enumerate(items, start=1):
            new_uri = retag(uri, cc, i)
            out_lines.append(new_uri)
            if old_num != i:
                mapping.append(f"{cc}{old_num} -> {cc}{i}")

    sys.stdout.write("\n".join(out_lines) + "\n")
    if mapping:
        print("\n# Renumber map:", file=sys.stderr)
        for row in mapping:
            print(row, file=sys.stderr)
    print(f"\n# Total: {len(out_lines)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
