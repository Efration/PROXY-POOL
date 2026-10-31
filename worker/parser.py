"""Protocol-aware parsing of proxy configuration URIs.

Supported schemes: ss, ssr, vmess, vless, trojan, tuic, hysteria,
hysteria2/hy2, socks/socks5 and http(s) proxies.

For every URI the parser extracts *only what the pipeline needs*:
host/port (the deduplication key), the fields the sing-box outbound builder
requires, and a verbatim copy of the original URI for output. Anything that
cannot be parsed yields ``None`` and is skipped by the caller -- malformed
entries must never abort a run.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote

from .decoder import b64_to_text

_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*)://")
_TOKEN_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s\"'<>\\]+")

SUPPORTED_SCHEMES = (
    "ss",
    "ssr",
    "vmess",
    "vless",
    "trojan",
    "tuic",
    "hysteria",
    "hysteria2",
    "hy2",
    "socks",
    "socks5",
    "http",
)


@dataclass
class ProxyConfig:
    """A parsed proxy URI plus its extraction result."""

    scheme: str  # canonical scheme (hysteria2, socks5, ...)
    host: str  # lowercase, IPv6 without brackets
    port: int
    raw: str  # the ORIGINAL usable URI, preserved verbatim for output
    fields: dict = field(default_factory=dict)  # protocol-specific data
    testable: bool = True  # can the connectivity-test core run this scheme?
    skip_reason: str = ""

    @property
    def endpoint(self) -> str:
        """THE deduplication key: host/IP + port, nothing else."""
        return f"{self.host.lower()}:{self.port}"

    def __str__(self) -> str:  # compact log representation
        return f"{self.scheme}://{self.endpoint}"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _split_host_port(authority: str) -> tuple[str, int] | None:
    """Split ``host:port`` (or ``[v6-host]:port``) with validation."""
    authority = authority.strip()
    if not authority:
        return None
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            return None
        host, rest = authority[1:end], authority[end + 1 :]
        if not rest.startswith(":"):
            return None
        port_s = rest[1:]
    else:
        if ":" not in authority:
            return None
        host, port_s = authority.rsplit(":", 1)
    host = host.strip().lower()
    if not host:
        return None
    try:
        port = int(port_s)
    except ValueError:
        return None
    if not 1 <= port <= 65535:
        return None
    return host, port


def _pct(s: str | None) -> str:
    try:
        return unquote(s or "")
    except Exception:
        return s or ""


def _query_dict(query: str) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        for key, value in parse_qsl(query, keep_blank_values=True):
            out.setdefault(key, value)
    except ValueError:
        pass
    return out


_B64_USERINFO_RE = re.compile(r"^[A-Za-z0-9+/=_\-]+$")


def _b64_userinfo(s: str) -> str | None:
    """Decode a Base64 userinfo blob (``dXNlcjpwYXNz`` -> ``user:pass``).

    Unlike subscriptions these blobs may be very short, so the generic
    decoder's length guard does not apply here; we require the decoded text
    to contain ':' as a plausibility check instead.
    """
    if len(s) < 4 or ":" in s or not _B64_USERINFO_RE.match(s):
        return None
    import base64

    padded = s + "=" * (-len(s) % 4)
    for fn in (
        lambda: base64.b64decode(padded, validate=True),
        lambda: base64.urlsafe_b64decode(padded),
    ):
        try:
            text = fn().decode("utf-8")
        except Exception:
            continue
        if ":" in text:
            return text
    return None


def _split_authority(rest: str) -> tuple[str, str, str]:
    """Return (userinfo, hostport, query) for a ``scheme://rest`` body."""
    no_frag = rest.split("#", 1)[0]
    authority, _, query = no_frag.partition("?")
    if "@" in authority:
        userinfo, hostport = authority.rsplit("@", 1)
    else:
        userinfo, hostport = "", authority
    return userinfo, hostport, query


# ---------------------------------------------------------------------------
# Per-scheme parsers
# ---------------------------------------------------------------------------


def _parse_ss(body: str, raw: str) -> ProxyConfig | None:
    # SIP002 has two common shapes:
    #   ss://<b64(method:password)>@host:port?plugin=...#name
    #   ss://<b64(method:password@host:port)>#name
    # plus an occasionally seen plain-userinfo variant:
    #   ss://method:password@host:port#name
    no_frag = body.split("#", 1)[0]
    core, _, query = no_frag.partition("?")
    userinfo = ""
    hostport = ""

    if "@" in core:
        left, right = core.rsplit("@", 1)
        dec = b64_to_text(left)
        if dec is not None and ":" in dec:
            userinfo, hostport = dec, right
        elif ":" in left:
            userinfo, hostport = _pct(left), right
        else:
            decoded = b64_to_text(core)  # legacy fully-encoded body
            if not decoded or "@" not in decoded:
                return None
            userinfo, hostport = decoded.rsplit("@", 1)
    else:
        decoded = b64_to_text(core)  # legacy fully-encoded body
        if not decoded or "@" not in decoded:
            return None
        userinfo, hostport = decoded.rsplit("@", 1)

    if not userinfo or ":" not in userinfo:
        return None
    method, password = userinfo.split(":", 1)
    parsed = _split_host_port(hostport)
    if not parsed:
        return None
    host, port = parsed

    plugin = _query_dict(query).get("plugin", "")
    return ProxyConfig(
        scheme="ss",
        host=host,
        port=port,
        raw=raw,
        fields={
            "method": method,
            "password": _pct(password),
            "plugin": _pct(plugin),
        },
    )


def _parse_ssr(body: str, raw: str) -> ProxyConfig | None:
    # ssr://<base64(host:port:protocol:method:obfs:b64(password)/?params)>
    text = b64_to_text(body.split("#", 1)[0])
    if not text:
        return None
    head, _, _params = text.partition("/?")
    parts = head.split(":")
    if len(parts) < 6:
        return None
    parsed = _split_host_port(f"{parts[0]}:{parts[1]}")
    if not parsed:
        return None
    host, port = parsed
    return ProxyConfig(
        scheme="ssr",
        host=host,
        port=port,
        raw=raw,
        fields={},
        testable=False,
        skip_reason="ssr is not supported by the sing-box test core",
    )


def _parse_vmess(body: str, raw: str) -> ProxyConfig | None:
    text = b64_to_text(body)
    if not text:
        return None
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    parsed = _split_host_port(f"{data.get('add', '')}:{data.get('port', '')}")
    if not parsed or not data.get("id"):
        return None
    host, port = parsed

    def _i(v: object) -> int:
        try:
            return int(str(v))
        except (TypeError, ValueError):
            return 0

    fields = {
        "uuid": str(data.get("id", "")),
        "alter_id": _i(data.get("aid", 0)),
        "security": str(data.get("scy") or data.get("security") or "auto"),
        "net": str(data.get("net") or "tcp").lower(),
        "header_type": str(data.get("type") or "none"),
        "host": str(data.get("host") or ""),
        "path": str(data.get("path") or ""),
        "tls": str(data.get("tls") or "").lower(),  # "", "tls", "none"
        "sni": str(data.get("sni") or ""),
        "alpn": str(data.get("alpn") or ""),
        "fp": str(data.get("fp") or ""),
        "service_name": str(
            data.get("serviceName") or data.get("servicename") or ""
        ),
    }
    cfg = ProxyConfig(scheme="vmess", host=host, port=port, raw=raw, fields=fields)
    if fields["net"] == "tcp" and fields["header_type"].lower() == "http":
        cfg.testable = False
        cfg.skip_reason = "vmess over tcp+http-obfs is not supported by sing-box"
    elif fields["net"] in ("kcp", "mkcp", "quic"):
        cfg.testable = False
        cfg.skip_reason = f"vmess over {fields['net']} is not supported by sing-box"
    return cfg


def _parse_vless(body: str, raw: str) -> ProxyConfig | None:
    userinfo, hostport, query = _split_authority(body)
    parsed = _split_host_port(hostport)
    if not parsed or not userinfo:
        return None
    host, port = parsed
    params = _query_dict(query)
    return ProxyConfig(
        scheme="vless",
        host=host,
        port=port,
        raw=raw,
        fields={"uuid": _pct(userinfo), "params": params},
    )


def _parse_trojan(body: str, raw: str) -> ProxyConfig | None:
    userinfo, hostport, query = _split_authority(body)
    parsed = _split_host_port(hostport)
    if not parsed or not userinfo:
        return None
    host, port = parsed
    return ProxyConfig(
        scheme="trojan",
        host=host,
        port=port,
        raw=raw,
        fields={"password": _pct(userinfo), "params": _query_dict(query)},
    )


def _parse_tuic(body: str, raw: str) -> ProxyConfig | None:
    userinfo, hostport, query = _split_authority(body)
    parsed = _split_host_port(hostport)
    if not parsed or ":" not in userinfo:
        return None
    host, port = parsed
    uuid, password = userinfo.split(":", 1)
    return ProxyConfig(
        scheme="tuic",
        host=host,
        port=port,
        raw=raw,
        fields={
            "uuid": _pct(uuid),
            "password": _pct(password),
            "params": _query_dict(query),
        },
    )


def _parse_hysteria(body: str, raw: str) -> ProxyConfig | None:
    _ui, hostport, query = _split_authority(body)
    parsed = _split_host_port(hostport)
    if not parsed:
        return None
    host, port = parsed
    return ProxyConfig(
        scheme="hysteria",
        host=host,
        port=port,
        raw=raw,
        fields={"params": _query_dict(query)},
    )


def _parse_hysteria2(body: str, raw: str) -> ProxyConfig | None:
    userinfo, hostport, query = _split_authority(body)
    parsed = _split_host_port(hostport)
    if not parsed:
        return None
    host, port = parsed
    return ProxyConfig(
        scheme="hysteria2",
        host=host,
        port=port,
        raw=raw,
        fields={"password": _pct(userinfo), "params": _query_dict(query)},
    )


def _parse_socks(body: str, raw: str) -> ProxyConfig | None:
    userinfo, hostport, query = _split_authority(body)
    parsed = _split_host_port(hostport)
    if not parsed:
        return None
    host, port = parsed
    username = password = ""
    if userinfo:
        if ":" in userinfo:
            u, p = userinfo.split(":", 1)
            username, password = _pct(u), _pct(p)
        else:
            decoded = _b64_userinfo(userinfo)
            if decoded:
                username, password = decoded.split(":", 1)
            else:
                username = _pct(userinfo)
    return ProxyConfig(
        scheme="socks5",
        host=host,
        port=port,
        raw=raw,
        fields={
            "username": username,
            "password": password,
            "params": _query_dict(query),
        },
    )


def _parse_http(body: str, raw: str) -> ProxyConfig | None:
    userinfo, hostport, query = _split_authority(body)
    parsed = _split_host_port(hostport)
    if not parsed:
        return None
    host, port = parsed
    username = password = ""
    if userinfo and ":" in userinfo:
        u, p = userinfo.split(":", 1)
        username, password = _pct(u), _pct(p)
    elif userinfo:
        decoded = _b64_userinfo(userinfo)
        if decoded:
            username, password = decoded.split(":", 1)
        else:
            username = _pct(userinfo)
    return ProxyConfig(
        scheme="http",
        host=host,
        port=port,
        raw=raw,
        fields={
            "username": username,
            "password": password,
            "params": _query_dict(query),
        },
    )


_PARSERS = {
    "ss": _parse_ss,
    "ssr": _parse_ssr,
    "vmess": _parse_vmess,
    "vless": _parse_vless,
    "trojan": _parse_trojan,
    "tuic": _parse_tuic,
    "hysteria": _parse_hysteria,
    "hysteria2": _parse_hysteria2,
    "hy2": _parse_hysteria2,
    "socks": _parse_socks,
    "socks5": _parse_socks,
    "http": _parse_http,
}

_TRAILING_JUNK = "\"'.,;<>)]}"


def parse_uri(token: str) -> ProxyConfig | None:
    """Parse one proxy URI token. Returns None for anything unsupported."""
    token = token.strip()
    # Do not strip ``<>`` out of a remark (``#<provider>name``). Trailing junk
    # is only removed from the URI proper, never from the fragment.
    if "#" in token:
        head, _, frag = token.partition("#")
        token = head.strip().rstrip(_TRAILING_JUNK) + "#" + frag
    else:
        token = token.strip(_TRAILING_JUNK)
    m = _SCHEME_RE.match(token)
    if not m:
        return None
    scheme = m.group(1).lower()
    parser = _PARSERS.get(scheme)
    if parser is None:
        return None
    body = token[m.end() :]
    try:
        return parser(body, token)
    except Exception:
        # Absolute guarantee: one malformed URI can never take down the run.
        return None


def parse_text(text: str) -> list[ProxyConfig]:
    """Extract every parseable proxy URI from (mixed, messy) content."""
    configs: list[ProxyConfig] = []
    for line in text.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Prefer the whole line so remarks with spaces/emoji stay intact
        # (``#🇩🇪 Germany 01``). Fall back to token scanning for mixed text.
        cfg = parse_uri(line)
        if cfg is not None:
            configs.append(cfg)
            continue
        for token in _TOKEN_RE.findall(line):
            cfg = parse_uri(token)
            if cfg is not None:
                configs.append(cfg)
    return configs
