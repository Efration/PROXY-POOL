"""Normalize subscription bodies into plain proxy URI lines.

A subscription may arrive as any of:

* raw proxy URIs (one per line, possibly mixed with comments)
* the same list Base64-encoded (standard, URL-safe, unpadded, nested)
* a sing-box JSON config / outbound list (plain or Base64-encoded)

This module always returns readable ``scheme://...`` lines so the rest of the
pipeline can keep using :func:`parser.parse_text`. Content that is already
normal is left untouched.
"""
from __future__ import annotations

import base64
import json
from typing import Any
from urllib.parse import quote

from .decoder import decode_body

# Outbound types that are routing/meta objects, not a proxy server.
_SKIP_TYPES = frozenset(
    {
        "direct",
        "block",
        "dns",
        "selector",
        "urltest",
        "fallback",
        "loadbalance",
        "pass",
        "reject",
        "blackhole",
        "dummy",
        "tor",
        "ssh",
        "shadowtls",
        "wireguard",
        "derp",
        "tailscale",
        "anytls",
        "naive",
        "shadowsocksr",
    }
)

_PROXY_TYPES = frozenset(
    {
        "shadowsocks",
        "ss",
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
        "https",
    }
)


def normalize_subscription(body: str) -> tuple[str, str]:
    """Return ``(uri_text, kind)`` ready for :func:`parser.parse_text`.

    ``kind`` is one of ``"sing-box"``, ``"uri"``. Base64 is decoded first in
    both cases; URI bodies that were Base64-encoded still report ``"uri"``
    because the payload itself is a URI list.
    """
    decoded = decode_body(body)
    uris = try_convert_singbox(decoded)
    if uris is not None:
        return "\n".join(uris), "sing-box"
    return decoded, "uri"


def try_convert_singbox(text: str) -> list[str] | None:
    """Convert a sing-box config/outbound list to URI lines.

    Returns ``None`` when ``text`` is not sing-box JSON so the caller can fall
    through to ordinary URI parsing. Returns a (possibly empty) list when the
    body *is* sing-box JSON.
    """
    data = _load_json(text)
    if data is None:
        return None

    outbounds = _extract_outbounds(data)
    if outbounds is None:
        return None

    uris: list[str] = []
    for item in outbounds:
        if not isinstance(item, dict):
            continue
        uri = outbound_to_uri(item)
        if uri:
            uris.append(uri)
    return uris


def outbound_to_uri(outbound: dict[str, Any]) -> str | None:
    """Convert one sing-box outbound object to a share-link URI."""
    otype = str(outbound.get("type") or "").strip().lower()
    if not otype or otype in _SKIP_TYPES:
        return None
    builder = _BUILDERS.get(otype)
    if builder is None:
        return None
    try:
        return builder(outbound)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# JSON loading / outbound extraction
# ---------------------------------------------------------------------------


def _load_json(text: str) -> Any | None:
    stripped = (text or "").lstrip("\ufeff").strip()
    if not stripped or stripped[0] not in "{[":
        return None
    for candidate in (stripped, _strip_jsonc(stripped)):
        try:
            return json.loads(candidate)
        except (json.JSONDecodeError, ValueError, TypeError):
            continue
    return None


def _strip_jsonc(text: str) -> str:
    """Best-effort removal of // and /* */ comments outside of strings."""
    out: list[str] = []
    i = 0
    n = len(text)
    in_str = False
    escape = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "/":
                i += 2
                while i < n and text[i] not in "\r\n":
                    i += 1
                continue
            if nxt == "*":
                i += 2
                while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                    i += 1
                i = min(n, i + 2)
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def _extract_outbounds(data: Any) -> list[Any] | None:
    """Return the outbound list if ``data`` looks like sing-box, else None."""
    if isinstance(data, dict):
        outs = data.get("outbounds")
        if isinstance(outs, list):
            return outs
        # A single outbound object posted as the whole body.
        if str(data.get("type") or "").strip().lower() in _PROXY_TYPES:
            return [data]
        return None
    if isinstance(data, list) and data:
        proxy_like = 0
        for item in data:
            if not isinstance(item, dict):
                continue
            otype = str(item.get("type") or "").strip().lower()
            if otype in _PROXY_TYPES and (item.get("server") or item.get("server_port")):
                proxy_like += 1
        if proxy_like:
            return data
    return None


# ---------------------------------------------------------------------------
# Small URI helpers
# ---------------------------------------------------------------------------


def _s(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value)


def _tag(outbound: dict[str, Any]) -> str:
    tag = _s(outbound.get("tag")).strip()
    return ("#" + quote(tag, safe="")) if tag else ""


def _hostport(host: str, port: int) -> str:
    host = host.strip()
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def _server_port(outbound: dict[str, Any]) -> tuple[str, int] | None:
    host = _s(outbound.get("server")).strip()
    port_raw = outbound.get("server_port")
    if port_raw is None:
        port_raw = outbound.get("port")
    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        return None
    if not host or not 1 <= port <= 65535:
        return None
    return host, port


def _qs(params: dict[str, str]) -> str:
    parts: list[str] = []
    for key, value in params.items():
        if value is None:
            continue
        text = str(value)
        if text == "":
            continue
        parts.append(f"{quote(str(key), safe='')}={quote(text, safe='')}")
    return ("?" + "&".join(parts)) if parts else ""


def _b64(text: str, urlsafe: bool = False) -> str:
    data = text.encode("utf-8")
    if urlsafe:
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
    return base64.b64encode(data).decode("ascii")


def _tls(outbound: dict[str, Any]) -> dict[str, Any]:
    tls = outbound.get("tls")
    return tls if isinstance(tls, dict) else {}


def _transport(outbound: dict[str, Any]) -> dict[str, Any]:
    tr = outbound.get("transport")
    return tr if isinstance(tr, dict) else {}


def _alpn(tls: dict[str, Any]) -> str:
    alpn = tls.get("alpn")
    if isinstance(alpn, list):
        return ",".join(_s(a) for a in alpn if _s(a))
    return _s(alpn)


def _fp(tls: dict[str, Any]) -> str:
    utls = tls.get("utls")
    if isinstance(utls, dict) and utls.get("enabled"):
        return _s(utls.get("fingerprint"))
    return ""


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return _s(value).strip().lower() in ("1", "true", "yes", "on")


def _header_host(tr: dict[str, Any]) -> str:
    headers = tr.get("headers")
    if isinstance(headers, dict):
        for key in ("Host", "host"):
            val = headers.get(key)
            if isinstance(val, list) and val:
                return _s(val[0])
            if val:
                return _s(val)
    host = tr.get("host")
    if isinstance(host, list) and host:
        return ",".join(_s(h) for h in host if _s(h))
    return _s(host)


def _ws_path(tr: dict[str, Any]) -> str:
    path = _s(tr.get("path")) or "/"
    early = tr.get("max_early_data")
    try:
        early_i = int(early)
    except (TypeError, ValueError):
        early_i = 0
    if early_i > 0:
        sep = "&" if "?" in path else "?"
        if "ed=" not in path:
            path = f"{path}{sep}ed={early_i}"
    return path


def _net_from_transport(tr: dict[str, Any]) -> str:
    t = _s(tr.get("type")).strip().lower()
    if t in ("", "tcp", "none"):
        return "tcp"
    if t == "http":
        return "h2"
    return t


def _security_params(tls: dict[str, Any]) -> dict[str, str]:
    params: dict[str, str] = {}
    if not tls:
        return params
    if tls.get("enabled") is False:
        params["security"] = "none"
        return params
    reality = tls.get("reality") if isinstance(tls.get("reality"), dict) else {}
    if reality.get("enabled"):
        params["security"] = "reality"
        params["pbk"] = _s(reality.get("public_key"))
        params["sid"] = _s(reality.get("short_id"))
    else:
        params["security"] = "tls"
    sni = _s(tls.get("server_name"))
    if sni:
        params["sni"] = sni
    alpn = _alpn(tls)
    if alpn:
        params["alpn"] = alpn
    fp = _fp(tls)
    if fp:
        params["fp"] = fp
    if _truthy(tls.get("insecure")):
        params["allowInsecure"] = "1"
        params["insecure"] = "1"
    return params


def _transport_params(tr: dict[str, Any]) -> dict[str, str]:
    params: dict[str, str] = {}
    net = _net_from_transport(tr)
    params["type"] = net
    if net == "tcp" and not tr:
        return params
    if net == "ws":
        params["path"] = _ws_path(tr)
        host = _header_host(tr)
        if host:
            params["host"] = host
    elif net == "grpc":
        service = _s(tr.get("service_name")) or _s(tr.get("path"))
        if service:
            params["serviceName"] = service
            params["path"] = service
    elif net in ("h2", "http", "httpupgrade"):
        path = _s(tr.get("path")) or "/"
        params["path"] = path.split("?")[0] or "/"
        host = _header_host(tr)
        if host:
            params["host"] = host
    return params


# ---------------------------------------------------------------------------
# Per-protocol builders
# ---------------------------------------------------------------------------


def _build_ss(o: dict[str, Any]) -> str | None:
    loc = _server_port(o)
    if not loc:
        return None
    host, port = loc
    method = _s(o.get("method"))
    password = _s(o.get("password"))
    if not method or not password:
        return None
    userinfo = _b64(f"{method}:{password}")
    plugin = _s(o.get("plugin"))
    plugin_opts = _s(o.get("plugin_opts"))
    query = ""
    if plugin:
        plugin_val = plugin if not plugin_opts else f"{plugin};{plugin_opts}"
        query = _qs({"plugin": plugin_val})
    return f"ss://{userinfo}@{_hostport(host, port)}{query}{_tag(o)}"


def _build_vmess(o: dict[str, Any]) -> str | None:
    loc = _server_port(o)
    if not loc:
        return None
    host, port = loc
    uuid = _s(o.get("uuid"))
    if not uuid:
        return None
    tls = _tls(o)
    tr = _transport(o)
    net = _net_from_transport(tr)
    path = ""
    header_type = "none"
    extra_host = ""
    service_name = ""
    if net == "ws":
        path = _ws_path(tr)
        extra_host = _header_host(tr)
    elif net == "grpc":
        service_name = _s(tr.get("service_name")) or _s(tr.get("path"))
        path = service_name
    elif net in ("h2", "http", "httpupgrade"):
        path = (_s(tr.get("path")) or "/").split("?")[0] or "/"
        extra_host = _header_host(tr)
    tls_flag = ""
    if tls.get("enabled", bool(tls.get("server_name") or tls)):
        tls_flag = "tls"
    try:
        aid = int(o.get("alter_id") or 0)
    except (TypeError, ValueError):
        aid = 0
    payload = {
        "v": "2",
        "ps": _s(o.get("tag")),
        "add": host,
        "port": str(port),
        "id": uuid,
        "aid": str(aid),
        "scy": _s(o.get("security")) or "auto",
        "net": "h2" if net == "http" else net,
        "type": header_type,
        "host": extra_host,
        "path": path,
        "tls": tls_flag,
        "sni": _s(tls.get("server_name")),
        "alpn": _alpn(tls),
        "fp": _fp(tls),
        "serviceName": service_name,
    }
    return "vmess://" + _b64(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))


def _build_vless(o: dict[str, Any]) -> str | None:
    loc = _server_port(o)
    if not loc:
        return None
    host, port = loc
    uuid = _s(o.get("uuid"))
    if not uuid:
        return None
    params: dict[str, str] = {}
    params.update(_transport_params(_transport(o)))
    params.update(_security_params(_tls(o)))
    flow = _s(o.get("flow"))
    if flow:
        params["flow"] = flow
    enc = _s(o.get("packet_encoding"))
    if enc:
        params["packetEncoding"] = enc
    return f"vless://{quote(uuid, safe='')}@{_hostport(host, port)}{_qs(params)}{_tag(o)}"


def _build_trojan(o: dict[str, Any]) -> str | None:
    loc = _server_port(o)
    if not loc:
        return None
    host, port = loc
    password = _s(o.get("password"))
    if not password:
        return None
    params: dict[str, str] = {}
    params.update(_transport_params(_transport(o)))
    params.update(_security_params(_tls(o) or {"enabled": True}))
    return (
        f"trojan://{quote(password, safe='')}@{_hostport(host, port)}"
        f"{_qs(params)}{_tag(o)}"
    )


def _build_tuic(o: dict[str, Any]) -> str | None:
    loc = _server_port(o)
    if not loc:
        return None
    host, port = loc
    uuid = _s(o.get("uuid"))
    password = _s(o.get("password"))
    if not uuid:
        return None
    tls = _tls(o)
    params = {
        "congestion_control": _s(o.get("congestion_control")) or "cubic",
        "sni": _s(tls.get("server_name")),
        "alpn": _alpn(tls),
        "udp_relay_mode": _s(o.get("udp_relay_mode")),
    }
    if _truthy(tls.get("insecure")):
        params["allow_insecure"] = "1"
        params["insecure"] = "1"
    userinfo = f"{quote(uuid, safe='')}:{quote(password, safe='')}"
    return f"tuic://{userinfo}@{_hostport(host, port)}{_qs(params)}{_tag(o)}"


def _build_hysteria(o: dict[str, Any]) -> str | None:
    loc = _server_port(o)
    if not loc:
        return None
    host, port = loc
    tls = _tls(o)
    params = {
        "auth": _s(o.get("auth_str")) or _s(o.get("auth")),
        "auth_str": _s(o.get("auth_str")) or _s(o.get("auth")),
        "peer": _s(tls.get("server_name")),
        "sni": _s(tls.get("server_name")),
        "alpn": _alpn(tls),
        "upmbps": _s(o.get("up_mbps")),
        "downmbps": _s(o.get("down_mbps")),
        "obfs": _s(o.get("obfs")) if not isinstance(o.get("obfs"), dict) else "",
    }
    if _truthy(tls.get("insecure")):
        params["insecure"] = "1"
    return f"hysteria://{_hostport(host, port)}{_qs(params)}{_tag(o)}"


def _build_hysteria2(o: dict[str, Any]) -> str | None:
    loc = _server_port(o)
    if not loc:
        return None
    host, port = loc
    password = _s(o.get("password"))
    tls = _tls(o)
    params: dict[str, str] = {
        "sni": _s(tls.get("server_name")),
    }
    if _truthy(tls.get("insecure")):
        params["insecure"] = "1"
    obfs = o.get("obfs")
    if isinstance(obfs, dict):
        obfs_type = _s(obfs.get("type")).lower()
        if obfs_type:
            params["obfs"] = obfs_type
        obfs_password = _s(obfs.get("password"))
        if obfs_password:
            params["obfs-password"] = obfs_password
    userinfo = quote(password, safe="") if password else ""
    prefix = f"{userinfo}@" if userinfo else ""
    return f"hysteria2://{prefix}{_hostport(host, port)}{_qs(params)}{_tag(o)}"


def _build_socks(o: dict[str, Any]) -> str | None:
    loc = _server_port(o)
    if not loc:
        return None
    host, port = loc
    username = _s(o.get("username"))
    password = _s(o.get("password"))
    if username:
        userinfo = f"{quote(username, safe='')}:{quote(password, safe='')}@"
    else:
        userinfo = ""
    return f"socks5://{userinfo}{_hostport(host, port)}{_tag(o)}"


def _build_http(o: dict[str, Any]) -> str | None:
    loc = _server_port(o)
    if not loc:
        return None
    host, port = loc
    username = _s(o.get("username"))
    password = _s(o.get("password"))
    if username:
        userinfo = f"{quote(username, safe='')}:{quote(password, safe='')}@"
    else:
        userinfo = ""
    return f"http://{userinfo}{_hostport(host, port)}{_tag(o)}"


_BUILDERS = {
    "shadowsocks": _build_ss,
    "ss": _build_ss,
    "vmess": _build_vmess,
    "vless": _build_vless,
    "trojan": _build_trojan,
    "tuic": _build_tuic,
    "hysteria": _build_hysteria,
    "hysteria2": _build_hysteria2,
    "hy2": _build_hysteria2,
    "socks": _build_socks,
    "socks5": _build_socks,
    "http": _build_http,
    "https": _build_http,
}
