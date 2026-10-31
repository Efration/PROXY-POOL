"""Base64 detection and decoding for subscription bodies.

Subscription providers deliver content in wildly different shapes:

* plain text, one proxy URI per line
* the *entire* body Base64-encoded (standard alphabet, with newlines inside
  the decoded text)
* URL-safe Base64 (``-`` and ``_`` instead of ``+`` and ``/``)
* Base64 with missing padding
* mixed bodies where some lines are plain URIs and others are Base64 blobs

This module normalizes all of the above into plain readable text. It never
raises: content that is not valid Base64 is simply returned untouched.
"""
from __future__ import annotations

import base64
import binascii

_B64_STD = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
)
_B64_URL = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="
)

# Below this length a "pure Base64" line is more likely to be ordinary text
# than an encoded URI, so we leave it alone.
_MIN_BLOB_LEN = 16


def _pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def b64_to_bytes(s: str) -> bytes | None:
    """Best-effort Base64 decode (standard or URL-safe). None if not Base64."""
    s = "".join(s.split())
    if len(s) < _MIN_BLOB_LEN:
        return None
    alphabet = set(s)
    is_std = alphabet <= _B64_STD
    is_url = alphabet <= _B64_URL
    if not (is_std or is_url):
        return None
    candidates = []
    if is_std:
        candidates.append(lambda: base64.b64decode(_pad(s), validate=True))
    if is_url or is_std:
        candidates.append(lambda: base64.urlsafe_b64decode(_pad(s)))
    for fn in candidates:
        try:
            data = fn()
        except (binascii.Error, ValueError):
            continue
        if data:
            return data
    return None


def b64_to_text(s: str) -> str | None:
    """Decode a Base64 string to UTF-8 text, or None if implausible."""
    data = b64_to_bytes(s)
    if data is None:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text


def _try_whole_body(text: str) -> str | None:
    """Handle subscriptions where the *entire* body is one Base64 blob."""
    blob = "".join(text.split())
    if not blob or "://" in blob:
        return None
    decoded = b64_to_text(blob)
    if decoded and decoded.strip():
        return decoded
    return None


def _decode_line(line: str) -> list[str] | None:
    """Decode a single Base64 line into one or more decoded lines."""
    blob = line.strip()
    if not blob or "://" in blob:
        return None
    decoded = b64_to_text(blob)
    if decoded is None:
        return None
    lines = [ln for ln in decoded.replace("\r\n", "\n").split("\n")]
    if not any("://" in ln for ln in lines):
        # Decoding "succeeded" but produced nothing proxy-like; the line was
        # probably ordinary text that happens to use Base64 characters.
        return None
    return lines


def decode_body(body: str) -> str:
    """Normalize a subscription body to plain text.

    Runs a few passes because some subscriptions are Base64(Base64(...)).
    Guaranteed not to raise; returns at least the original content.
    """
    current = body
    for _ in range(4):
        whole = _try_whole_body(current)
        if whole is not None and whole != current:
            current = whole
            continue

        out: list[str] = []
        changed = False
        for line in current.replace("\r\n", "\n").split("\n"):
            decoded = _decode_line(line)
            if decoded is not None:
                out.extend(decoded)
                changed = True
            else:
                out.append(line)
        current = "\n".join(out)
        if not changed:
            break
    return current
