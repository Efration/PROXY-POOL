"""Derive a subscription provider name and prefix it onto config remarks.

The provider is taken from the subscription URL (GitHub owner, or the
meaningful domain label). Only the remark/name is changed: the original
name bytes are left intact and the rest of the URI is untouched.
"""
from __future__ import annotations

import base64
import json
import re
from urllib.parse import urlparse

from .decoder import b64_to_text

# Left-most host labels that are infrastructure, not a provider identity.
_GENERIC_LABELS = frozenset(
    {
        "www",
        "www2",
        "www3",
        "sub",
        "raw",
        "api",
        "cdn",
        "static",
        "download",
        "dl",
        "mirror",
        "m",
        "ipv6",
        "ftp",
        "origin",
        "files",
        "file",
        "node",
        "nodes",
        "cdn-cgi",
    }
)

_GITHUB_OWNER_RE = re.compile(
    r"(?:(?:www\.)?github\.com|raw\.githubusercontent\.com|"
    r"gist\.github(?:usercontent)?\.com)/([^/]+)/",
    re.IGNORECASE,
)
_JSDELIVR_GH_RE = re.compile(r"jsdelivr\.net/gh/([^/@/]+)", re.IGNORECASE)
_GITLAB_OWNER_RE = re.compile(
    r"(?:(?:www\.)?gitlab\.com)/([^/]+)/", re.IGNORECASE
)


def provider_from_url(url: str) -> str:
    """Return the provider identity for a subscription URL, or ``""``."""
    url = (url or "").strip()
    if not url:
        return ""

    match = _GITHUB_OWNER_RE.search(url)
    if match:
        owner = match.group(1).strip()
        if owner and owner.lower() not in {"http:", "https:", "www"}:
            return owner

    match = _JSDELIVR_GH_RE.search(url)
    if match:
        owner = match.group(1).strip()
        if owner:
            return owner

    match = _GITLAB_OWNER_RE.search(url)
    if match:
        owner = match.group(1).strip()
        if owner:
            return owner

    host = _hostname(url)
    return _provider_from_host(host)


def prefix_config_name(raw: str, provider: str) -> str:
    """Return ``raw`` with ``<provider>`` prepended to the remark only."""
    provider = (provider or "").strip()
    if not provider or not raw:
        return raw
    marker = f"<{provider}>"
    scheme = raw.split("://", 1)[0].lower() if "://" in raw else ""
    if scheme == "vmess":
        return _prefix_vmess(raw, marker)
    return _prefix_fragment(raw, marker)


def apply_provider_prefix(raw: str, url: str) -> str:
    """Convenience: derive the provider from ``url`` and prefix ``raw``."""
    return prefix_config_name(raw, provider_from_url(url))


# ---------------------------------------------------------------------------
# URL → provider
# ---------------------------------------------------------------------------


def _hostname(url: str) -> str:
    parsed = urlparse(url)
    netloc = parsed.netloc or ""
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[-1]
    if netloc.startswith("["):
        end = netloc.find("]")
        return netloc[1:end] if end > 0 else netloc
    return netloc.split(":", 1)[0]


def _provider_from_host(host: str) -> str:
    host = (host or "").strip().rstrip(".")
    if not host:
        return ""
    if _looks_like_ip(host):
        return ""
    labels = [part for part in host.split(".") if part]
    while len(labels) > 1 and labels[0].lower() in _GENERIC_LABELS:
        labels.pop(0)
    if not labels:
        return ""
    return labels[0]


def _looks_like_ip(host: str) -> bool:
    if ":" in host:
        return True  # IPv6
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return True
    return False


# ---------------------------------------------------------------------------
# Remark rewriting (name only)
# ---------------------------------------------------------------------------


def _prefix_fragment(raw: str, marker: str) -> str:
    hash_at = _fragment_index(raw)
    if hash_at >= 0:
        name = raw[hash_at + 1 :]
        if name.startswith(marker):
            return raw
        return raw[: hash_at + 1] + marker + name
    return raw + "#" + marker


def _fragment_index(raw: str) -> int:
    """Index of the remark ``#``, ignoring ``#`` inside an unencoded IPv6 host."""
    scheme_end = raw.find("://")
    start = scheme_end + 3 if scheme_end >= 0 else 0
    return raw.find("#", start)


def _prefix_vmess(raw: str, marker: str) -> str:
    sep = raw.find("://")
    rest = raw[sep + 3 :] if sep >= 0 else raw
    frag = ""
    hash_at = rest.find("#")
    if hash_at >= 0:
        rest, frag = rest[:hash_at], rest[hash_at:]  # frag includes '#'

    decoded = b64_to_text(rest)
    if decoded:
        try:
            data = json.loads(decoded)
        except (json.JSONDecodeError, ValueError):
            data = None
        if isinstance(data, dict):
            ps = data.get("ps")
            if ps is None:
                name = ""
            elif isinstance(ps, str):
                name = ps
            else:
                name = str(ps)
            if not name.startswith(marker):
                data["ps"] = marker + name
            payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
            new_body = base64.b64encode(payload.encode("utf-8")).decode("ascii")
            prefix = raw[: sep + 3] if sep >= 0 else "vmess://"
            if frag:
                frag_name = frag[1:]
                if not frag_name.startswith(marker):
                    frag = "#" + marker + frag_name
            return prefix + new_body + frag

    return _prefix_fragment(raw, marker)
