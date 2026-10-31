"""Real protocol-level connectivity testing via the sing-box core.

For every candidate configuration we:

1. convert the URI into a sing-box outbound (protocol-aware),
2. generate a minimal sing-box config: local SOCKS/HTTP "mixed" inbound +
   the candidate outbound,
3. launch the sing-box binary,
4. perform ONE lightweight HTTP(S) request *through the proxy* with curl
   (e.g. https://www.gstatic.com/generate_204),
5. declare the configuration healthy only when the request succeeds.

This is deliberately NOT an ICMP ping and NOT a bare TCP-connect check: a
config is healthy only if the actual proxy tunnel works end to end.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from .parser import ProxyConfig

_UNSUPPORTED = "__unsupported__"


# ---------------------------------------------------------------------------
# Outbound construction (proxy URI -> sing-box outbound JSON)
# ---------------------------------------------------------------------------


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def _tls_block(
    server_name: str = "",
    insecure: bool = False,
    alpn: str | None = None,
    fp: str = "",
    reality_pbk: str = "",
    reality_sid: str = "",
) -> dict:
    tls: dict = {"enabled": True}
    if server_name:
        tls["server_name"] = server_name
    if insecure:
        tls["insecure"] = True
    if alpn:
        names = [a.strip() for a in alpn.split(",") if a.strip()]
        if names:
            tls["alpn"] = names
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    if reality_pbk:
        reality: dict = {"enabled": True, "public_key": reality_pbk}
        if reality_sid:
            reality["short_id"] = reality_sid
        tls["reality"] = reality
    return tls


def _split_early_data(path: str) -> tuple[str, int]:
    """v2ray convention: /path?ed=2048 means WebSocket early-data."""
    if not path:
        return "/", 0
    if "?" not in path:
        return path, 0
    base, _, query = path.partition("?")
    for pair in query.split("&"):
        if pair.startswith("ed="):
            try:
                return base or "/", max(0, int(pair[3:]))
            except ValueError:
                return base or "/", 0
    return path, 0


def _transport(
    network: str,
    path: str = "",
    host: str = "",
    service_name: str = "",
    header_type: str = "",
) -> dict | str | None:
    """Map v2ray-style transport params to a sing-box transport block.

    Returns None for plain TCP, a dict for a supported transport, or the
    ``_UNSUPPORTED`` sentinel for networks sing-box cannot run.
    """
    network = (network or "tcp").strip().lower()
    if network in ("", "tcp", "none"):
        if (header_type or "").strip().lower() not in ("", "none"):
            return _UNSUPPORTED  # tcp header obfuscation has no sing-box equivalent
        return None
    if network == "ws":
        ws_path, early = _split_early_data(path)
        ws: dict = {"type": "ws", "path": ws_path or "/"}
        if host:
            ws["headers"] = {"Host": host}
        if early > 0:
            ws["max_early_data"] = early
            ws["early_data_header_name"] = "Sec-WebSocket-Protocol"
        return ws
    if network == "grpc":
        return {"type": "grpc", "service_name": service_name or path or ""}
    if network in ("h2", "http"):
        h2: dict = {"type": "http"}
        if host:
            h2["host"] = [h.strip() for h in host.split(",") if h.strip()]
        h2["path"] = (path or "/").split("?")[0] or "/"
        return h2
    if network == "httpupgrade":
        hu: dict = {"type": "httpupgrade", "path": (path or "/").split("?")[0] or "/"}
        if host:
            hu["host"] = host
        return hu
    return _UNSUPPORTED


def _first(params: dict, *keys: str, default: str = "") -> str:
    for key in keys:
        value = params.get(key)
        if value:
            return value
    return default


def _outbound_ss(c: ProxyConfig) -> dict | None:
    f = c.fields
    outbound: dict = {
        "type": "shadowsocks",
        "tag": "proxy",
        "server": c.host,
        "server_port": c.port,
        "method": f.get("method", ""),
        "password": f.get("password", ""),
    }
    plugin = f.get("plugin") or ""
    if plugin:
        parts = [p for p in plugin.split(";") if p]
        name = parts[0] if parts else ""
        if name in ("obfs-local", "v2ray-plugin"):
            outbound["plugin"] = name
            outbound["plugin_opts"] = ";".join(parts[1:])
        # Unknown plugins make the config untestable -> caller drops it.
    return outbound


def _outbound_vmess(c: ProxyConfig) -> dict | None:
    f = c.fields
    outbound: dict = {
        "type": "vmess",
        "tag": "proxy",
        "server": c.host,
        "server_port": c.port,
        "uuid": f.get("uuid", ""),
        "security": f.get("security") or "auto",
        "alter_id": f.get("alter_id", 0),
    }
    if f.get("tls") == "tls":
        outbound["tls"] = _tls_block(
            server_name=f.get("sni") or f.get("host") or c.host,
            alpn=f.get("alpn") or None,
            fp=f.get("fp") or "",
        )
    tr = _transport(
        f.get("net", "tcp"),
        path=f.get("path", ""),
        host=f.get("host", ""),
        service_name=f.get("service_name", ""),
        header_type=f.get("header_type", ""),
    )
    if tr is _UNSUPPORTED:
        return None
    if tr:
        outbound["transport"] = tr
    return outbound


def _outbound_vless(c: ProxyConfig) -> dict | None:
    f = c.fields
    p = f.get("params", {})
    outbound: dict = {
        "type": "vless",
        "tag": "proxy",
        "server": c.host,
        "server_port": c.port,
        "uuid": f.get("uuid", ""),
    }
    flow = (p.get("flow") or "").strip()
    if flow.startswith("xtls-rprx-vision"):
        outbound["flow"] = "xtls-rprx-vision"

    security = (p.get("security") or "").lower()
    if security in ("tls", "xtls", "reality"):
        if security == "reality":
            outbound["tls"] = _tls_block(
                server_name=_first(p, "sni", "peer"),
                fp=p.get("fp") or "",
                reality_pbk=p.get("pbk") or "",
                reality_sid=p.get("sid") or "",
            )
        else:
            outbound["tls"] = _tls_block(
                server_name=_first(p, "sni", "peer") or c.host,
                insecure=_truthy(_first(p, "allowInsecure", "allow_insecure", "insecure")),
                alpn=p.get("alpn"),
                fp=p.get("fp") or "",
            )

    tr = _transport(
        _first(p, "type", "network", default="tcp"),
        path=_first(p, "path"),
        host=_first(p, "host"),
        service_name=_first(p, "serviceName", "service_name"),
        header_type=_first(p, "headerType"),
    )
    if tr is _UNSUPPORTED:
        return None
    if tr:
        outbound["transport"] = tr

    packet_encoding = (p.get("packetEncoding") or p.get("packet_encoding") or "").lower()
    if packet_encoding in ("xudp", "packetaddr"):
        outbound["packet_encoding"] = packet_encoding
    return outbound


def _outbound_trojan(c: ProxyConfig) -> dict | None:
    f = c.fields
    p = f.get("params", {})
    outbound: dict = {
        "type": "trojan",
        "tag": "proxy",
        "server": c.host,
        "server_port": c.port,
        "password": f.get("password", ""),
        "tls": _tls_block(
            server_name=_first(p, "sni", "peer") or c.host,
            insecure=_truthy(_first(p, "allowInsecure", "allow_insecure", "insecure")),
            alpn=p.get("alpn"),
            fp=p.get("fp") or "",
        ),
    }
    tr = _transport(
        _first(p, "type", "network", default="tcp"),
        path=_first(p, "path"),
        host=_first(p, "host"),
        service_name=_first(p, "serviceName", "service_name"),
        header_type=_first(p, "headerType"),
    )
    if tr is _UNSUPPORTED:
        return None
    if tr:
        outbound["transport"] = tr
    return outbound


def _outbound_tuic(c: ProxyConfig) -> dict | None:
    f = c.fields
    p = f.get("params", {})
    return {
        "type": "tuic",
        "tag": "proxy",
        "server": c.host,
        "server_port": c.port,
        "uuid": f.get("uuid", ""),
        "password": f.get("password", ""),
        "congestion_control": p.get("congestion_control") or "cubic",
        "tls": _tls_block(
            server_name=_first(p, "sni", "peer") or c.host,
            insecure=_truthy(
                _first(p, "allow_insecure", "allowInsecure", "insecure")
            ),
            alpn=p.get("alpn"),
        ),
    }


def _outbound_hysteria(c: ProxyConfig) -> dict | None:
    f = c.fields
    p = f.get("params", {})

    def _mbps(*keys: str, default: int = 0) -> int:
        for key in keys:
            try:
                value = int(str(p.get(key) or ""))
                if value > 0:
                    return value
            except ValueError:
                continue
        return default

    outbound: dict = {
        "type": "hysteria",
        "tag": "proxy",
        "server": c.host,
        "server_port": c.port,
        "up_mbps": _mbps("upmbps", "up", default=100),
        "down_mbps": _mbps("downmbps", "down", default=100),
    }
    auth = p.get("auth_str") or p.get("auth") or ""
    if auth:
        outbound["auth_str"] = auth
    obfs = p.get("obfsParam") or ""
    if not obfs:
        raw_obfs = p.get("obfs") or ""
        if raw_obfs and raw_obfs.lower() != "xplus":
            obfs = raw_obfs
        # xplus-style links sometimes carry the password in obfsParam only.
    if obfs:
        outbound["obfs"] = obfs
    outbound["tls"] = _tls_block(
        server_name=_first(p, "peer", "sni") or c.host,
        insecure=_truthy(p.get("insecure")),
        alpn=p.get("alpn"),
    )
    return outbound


def _outbound_hysteria2(c: ProxyConfig) -> dict | None:
    f = c.fields
    p = f.get("params", {})
    outbound: dict = {
        "type": "hysteria2",
        "tag": "proxy",
        "server": c.host,
        "server_port": c.port,
        "password": f.get("password", ""),
    }
    obfs = (p.get("obfs") or "").lower()
    if obfs == "salamander":
        obfs_password = _first(p, "obfs-password", "obfs_password")
        if obfs_password:
            outbound["obfs"] = {"type": "salamander", "password": obfs_password}
    # NOTE: hysteria2 port-hopping ("mport"/"ports" params) is intentionally
    # not converted -- sing-box 1.10 does not support it; the authority port
    # of the URI is always tested as-is.
    outbound["tls"] = _tls_block(
        server_name=_first(p, "sni", "peer") or c.host,
        insecure=_truthy(p.get("insecure")),
    )
    return outbound


def _outbound_socks(c: ProxyConfig) -> dict | None:
    f = c.fields
    outbound: dict = {
        "type": "socks",
        "tag": "proxy",
        "server": c.host,
        "server_port": c.port,
        "version": "5",
    }
    if f.get("username"):
        outbound["username"] = f["username"]
        outbound["password"] = f.get("password", "")
    return outbound


def _outbound_http(c: ProxyConfig) -> dict | None:
    f = c.fields
    outbound: dict = {
        "type": "http",
        "tag": "proxy",
        "server": c.host,
        "server_port": c.port,
    }
    if f.get("username"):
        outbound["username"] = f["username"]
        outbound["password"] = f.get("password", "")
    return outbound


_OUTBOUND_BUILDERS = {
    "ss": _outbound_ss,
    "vmess": _outbound_vmess,
    "vless": _outbound_vless,
    "trojan": _outbound_trojan,
    "tuic": _outbound_tuic,
    "hysteria": _outbound_hysteria,
    "hysteria2": _outbound_hysteria2,
    "socks5": _outbound_socks,
    "http": _outbound_http,
}


def build_outbound(c: ProxyConfig) -> dict | None:
    """Build a sing-box outbound for a parsed config (None = cannot test)."""
    if not c.testable:
        return None
    builder = _OUTBOUND_BUILDERS.get(c.scheme)
    if builder is None:
        return None
    try:
        return builder(c)
    except Exception:
        return None


def build_core_config(c: ProxyConfig, listen_port: int) -> dict | None:
    """Full sing-box config: mixed inbound + candidate outbound + direct."""
    outbound = build_outbound(c)
    if outbound is None:
        return None
    return {
        "log": {"level": "error", "timestamp": False},
        "dns": {
            "servers": [
                {"tag": "dns-local", "address": "local", "detour": "direct"},
            ]
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "in",
                "listen": "127.0.0.1",
                "listen_port": listen_port,
            }
        ],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "route": {"final": "proxy"},
    }


# ---------------------------------------------------------------------------
# Core resolution & preflight
# ---------------------------------------------------------------------------


def find_core(path_hint: str, root: Path) -> str | None:
    """Locate the sing-box binary."""
    candidates: list[str] = []
    env_path = os.environ.get("SING_BOX_PATH", "").strip()
    if env_path:
        candidates.append(env_path)
    if path_hint:
        candidates.append(path_hint)
    candidates.append(str(root / "tools" / "sing-box"))

    for candidate in candidates:
        if os.path.sep in candidate or candidate.startswith((".", "/")):
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        else:
            found = shutil.which(candidate)
            if found:
                return found
    return None


def preflight(core_path: str) -> str:
    """Verify the core runs; return its version string or raise SystemExit."""
    try:
        proc = subprocess.run(
            [core_path, "version"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SystemExit(
            f"[preflight] cannot run sing-box at '{core_path}': {exc}. "
            "The workflow downloads it automatically; for local runs see README."
        )
    output = (proc.stdout or proc.stderr or "").strip().splitlines()
    return output[0] if output else "sing-box (unknown version)"


# ---------------------------------------------------------------------------
# The test harness
# ---------------------------------------------------------------------------


@dataclass
class CoreResult:
    ok: bool
    detail: str
    http_code: int = 0
    elapsed_ms: float = 0.0


class CoreTester:
    """Launches sing-box per candidate and probes through the real proxy."""

    def __init__(
        self,
        core_path: str,
        test_url: str,
        timeout_seconds: int,
        startup_timeout_seconds: int,
        curl_path: str = "curl",
    ) -> None:
        self.core_path = core_path
        self.test_url = test_url
        self.timeout = timeout_seconds
        self.startup_timeout = startup_timeout_seconds
        self.curl_path = curl_path

    # -- one attempt ------------------------------------------------------

    def test_once(self, cfg: ProxyConfig, listen_port: int) -> CoreResult:
        if not cfg.testable:
            return CoreResult(False, f"untestable: {cfg.skip_reason}")
        config = build_core_config(cfg, listen_port)
        if config is None:
            return CoreResult(False, "cannot build a core config for this URI")

        started = time.monotonic()
        tmp = Path(tempfile.mkdtemp(prefix="ppw-"))
        proc: subprocess.Popen | None = None
        try:
            config_path = tmp / "config.json"
            log_path = tmp / "core.log"
            config_path.write_text(json.dumps(config), encoding="utf-8")

            with log_path.open("wb") as log_file:
                proc = subprocess.Popen(
                    [self.core_path, "run", "-c", str(config_path)],
                    cwd=str(tmp),
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                ready, last_error = self._wait_ready(proc, listen_port)
                if not ready:
                    tail = self._log_tail(log_path)
                    return CoreResult(
                        False,
                        f"core failed to start ({last_error})" + (f": {tail}" if tail else ""),
                    )

                return self._probe(listen_port, started)
        finally:
            self._stop(proc)
            shutil.rmtree(tmp, ignore_errors=True)

    def _wait_ready(
        self, proc: subprocess.Popen, port: int
    ) -> tuple[bool, str]:
        deadline = time.monotonic() + self.startup_timeout
        while time.monotonic() < deadline:
            rc = proc.poll()
            if rc is not None:
                return False, f"core exited with code {rc}"
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                    return True, ""
            except OSError:
                time.sleep(0.05)
        return False, "core did not open its local port in time"

    def _probe(self, listen_port: int, started: float) -> CoreResult:
        try:
            cp = subprocess.run(
                [
                    self.curl_path,
                    "--silent",
                    "--output", os.devnull,
                    "--write-out", "%{http_code}",
                    "--max-time", str(self.timeout),
                    "--proxy", f"socks5h://127.0.0.1:{listen_port}",
                    self.test_url,
                ],
                capture_output=True,
                text=True,
                timeout=self.timeout + 10,
            )
        except subprocess.TimeoutExpired:
            return CoreResult(False, "probe timed out")
        elapsed_ms = (time.monotonic() - started) * 1000.0

        try:
            http_code = int((cp.stdout or "0").strip() or "0")
        except ValueError:
            http_code = 0

        if cp.returncode == 0 and 200 <= http_code < 400:
            return CoreResult(
                True, f"ok http {http_code}", http_code, elapsed_ms=elapsed_ms
            )
        stderr = (cp.stderr or "").strip().replace("\n", " ")[:140]
        return CoreResult(
            False,
            f"curl exit {cp.returncode} http {http_code}"
            + (f" ({stderr})" if stderr else ""),
            http_code,
            elapsed_ms=elapsed_ms,
        )

    @staticmethod
    def _log_tail(log_path: Path, limit: int = 200) -> str:
        try:
            content = log_path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return ""
        return content.replace("\n", " ")[-limit:]

    @staticmethod
    def _stop(proc: subprocess.Popen | None) -> None:
        if proc is None:
            return
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=1.5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=1.5)
        except OSError:
            pass
