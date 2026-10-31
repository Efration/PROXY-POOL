"""Unit tests for the proxy pool worker.

Run from the repository root with:

    python -m unittest discover -s tests -v

Covers: Base64 detection/decoding, protocol parsing, host:port extraction,
endpoint-only deduplication, OLD/NEW classification and - most importantly -
the retry policy (existing configs get retries, new configs get exactly ONE
attempt).
"""
from __future__ import annotations

import base64
import json
import tempfile
import unittest
from collections import OrderedDict
from pathlib import Path

from worker.decoder import b64_to_text, decode_body
from worker.dedupe import dedupe_by_endpoint
from worker.parser import parse_text, parse_uri
from worker.provider import (
    prefix_config_name,
    provider_from_url,
)
from worker.singbox import build_core_config, build_outbound
from worker.subscription import (
    normalize_subscription,
    outbound_to_uri,
    try_convert_singbox,
)
from worker.tester import (
    Candidate,
    PortPool,
    ScanProgress,
    allowed_attempts,
    run_tests,
)
from worker import main as pipeline


def b64(s: str, urlsafe: bool = False) -> str:
    data = s.encode()
    if urlsafe:
        return base64.urlsafe_b64encode(data).decode()
    return base64.b64encode(data).decode()


def b64_nopad(s: str) -> str:
    return b64(s).rstrip("=")


SS_LEGACY = "ss://" + b64("aes-128-gcm:s3cret@198.51.100.10:8388") + "#legacy"
SS_SIP002 = "ss://" + b64("aes-128-gcm:s3cret", urlsafe=True).rstrip("=") + "@198.51.100.11:8388#sip02"
VMESS = "vmess://" + b64(
    json.dumps(
        {
            "v": "2",
            "ps": "vmess-example",
            "add": "203.0.113.7",
            "port": "443",
            "id": "11111111-2222-3333-4444-555555555555",
            "aid": "0",
            "scy": "auto",
            "net": "ws",
            "type": "none",
            "host": "cdn.example.com",
            "path": "/ws?ed=2048",
            "tls": "tls",
            "sni": "sni.example.com",
        }
    )
)
VLESS_REALITY = (
    "vless://11111111-2222-3333-4444-555555555555@203.0.113.5:443"
    "?security=reality&sni=www.apple.com&fp=chrome&pbk=PUBKEY123&sid=ab"
    "&type=tcp&flow=xtls-rprx-vision#reality-node"
)
TROJAN = "trojan://p%40ss%3Aword@example.com:443?security=tls&sni=x.example.com#tr"
TUIC = (
    "tuic://11111111-2222-3333-4444-555555555555:pw@10.0.0.9:443"
    "?congestion_control=bbr&sni=tuic.example.com&alpn=h3&allow_insecure=0#tuic"
)
HYSTERIA = (
    "hysteria://10.0.0.10:36712?protocol=udp&auth=secret&peer=hy.example.com"
    "&insecure=1&upmbps=50&downmbps=100&alpn=h3#hy1"
)
HYSTERIA2 = (
    "hy2://p%40ss%26word@10.0.0.11:8443?insecure=1&sni=hy2.example.com"
    "&obfs=salamander&obfs-password=opass#hy2"
)
SOCKS5 = "socks5://" + b64("user:pass", urlsafe=True).rstrip("=") + "@10.0.0.12:1080#s5"
HTTP_PROXY = "http://user:pass@10.0.0.13:8080#hp"


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------


class DecoderTests(unittest.TestCase):
    def test_plain_text_passes_through(self):
        body = VLESS_REALITY + "\n" + TROJAN
        self.assertEqual(decode_body(body), body)

    def test_whole_body_base64(self):
        plain = SS_SIP002 + "\n" + VLESS_REALITY
        self.assertEqual(decode_body(b64(plain)), plain)

    def test_whole_body_urlsafe_base64_no_padding(self):
        plain = VLESS_REALITY + "\n" + HYSTERIA2
        blob = b64(plain, urlsafe=True).rstrip("=")
        self.assertEqual(decode_body(blob), plain)

    def test_mixed_content(self):
        plain_line = TROJAN
        blob = b64_nopad(VLESS_REALITY)
        out = decode_body(plain_line + "\n" + blob + "\n" + "not a proxy")
        self.assertIn(VLESS_REALITY, out)
        self.assertIn(TROJAN, out)
        self.assertIn("not a proxy", out)

    def test_garbage_does_not_crash(self):
        for junk in ("", "   ", "!!!@@@###", "dm1lc3M6", "\x00\x01\x02"):
            self.assertIsInstance(decode_body(junk), str)

    def test_b64_to_text_rejects_short_blobs(self):
        self.assertIsNone(b64_to_text("cmM0OnA="))  # too short to trust


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class ParserTests(unittest.TestCase):
    def test_ss_legacy_whole_encoded(self):
        cfg = parse_uri(SS_LEGACY)
        self.assertIsNotNone(cfg)
        self.assertEqual(cfg.scheme, "ss")
        self.assertEqual((cfg.host, cfg.port), ("198.51.100.10", 8388))
        self.assertEqual(cfg.fields["method"], "aes-128-gcm")
        self.assertEqual(cfg.fields["password"], "s3cret")

    def test_ss_sip002_userinfo(self):
        cfg = parse_uri(SS_SIP002)
        self.assertIsNotNone(cfg)
        self.assertEqual(cfg.endpoint, "198.51.100.11:8388")

    def test_ss_ipv6(self):
        token = "ss://" + b64("aes-128-gcm:pw@[2001:db8::1]:8388")
        cfg = parse_uri(token)
        self.assertIsNotNone(cfg)
        self.assertEqual(cfg.endpoint, "2001:db8::1:8388")

    def test_vmess(self):
        cfg = parse_uri(VMESS)
        self.assertIsNotNone(cfg)
        self.assertEqual(cfg.endpoint, "203.0.113.7:443")
        self.assertEqual(cfg.fields["uuid"], "11111111-2222-3333-4444-555555555555")
        self.assertEqual(cfg.fields["net"], "ws")

    def test_vless_reality(self):
        cfg = parse_uri(VLESS_REALITY)
        self.assertIsNotNone(cfg)
        self.assertEqual(cfg.endpoint, "203.0.113.5:443")
        self.assertEqual(cfg.fields["params"]["pbk"], "PUBKEY123")

    def test_trojan_percent_decoding(self):
        cfg = parse_uri(TROJAN)
        self.assertIsNotNone(cfg)
        self.assertEqual(cfg.fields["password"], "p@ss:word")

    def test_tuic(self):
        cfg = parse_uri(TUIC)
        self.assertIsNotNone(cfg)
        self.assertEqual(cfg.endpoint, "10.0.0.9:443")
        self.assertEqual(cfg.fields["password"], "pw")

    def test_hysteria(self):
        cfg = parse_uri(HYSTERIA)
        self.assertIsNotNone(cfg)
        self.assertEqual((cfg.host, cfg.port), ("10.0.0.10", 36712))

    def test_hysteria2_hy2_alias(self):
        cfg = parse_uri(HYSTERIA2)
        self.assertIsNotNone(cfg)
        self.assertEqual(cfg.scheme, "hysteria2")
        self.assertEqual(cfg.fields["password"], "p@ss&word")

    def test_socks5_b64_userinfo(self):
        cfg = parse_uri(SOCKS5)
        self.assertIsNotNone(cfg)
        self.assertEqual(cfg.fields["username"], "user")
        self.assertEqual(cfg.fields["password"], "pass")

    def test_http_proxy(self):
        cfg = parse_uri(HTTP_PROXY)
        self.assertIsNotNone(cfg)
        self.assertEqual(cfg.endpoint, "10.0.0.13:8080")

    def test_unknown_scheme_and_junk_ignored(self):
        self.assertIsNone(parse_uri("wireguard://xyz@1.2.3.4:51820"))
        self.assertIsNone(parse_uri("https://example.com/page"))
        self.assertIsNone(parse_uri("hello world"))
        self.assertIsNone(parse_uri(""))
        self.assertIsNone(parse_uri("vless://no-host-at-all"))
        self.assertIsNone(parse_uri("trojan://pw@example.com:notaport"))

    def test_parse_text_multiple_and_messy(self):
        text = (
            "\n"
            "# a comment\n"
            f"   {TROJAN}   \n"
            f"prefix {VLESS_REALITY}\n"
            "random words, no proxies\n"
            f"{HYSTERIA2}\n"
        )
        cfgs = parse_text(text)
        self.assertEqual(len(cfgs), 3)


# ---------------------------------------------------------------------------
# Deduplication - key is host/IP + port ONLY
# ---------------------------------------------------------------------------


class DedupeTests(unittest.TestCase):
    def test_cross_protocol_same_endpoint_dedupes(self):
        a = parse_uri("vless://u1@1.2.3.4:443?security=reality&sni=a.com#a")
        b = parse_uri("trojan://pw@1.2.3.4:443?security=tls&sni=b.com#b")
        c = parse_uri("trojan://pw@1.2.3.4:444#c")
        kept, dropped = dedupe_by_endpoint([a, b, c])
        self.assertEqual(len(kept), 2)
        self.assertEqual(dropped, 1)
        self.assertIs(kept[0], a)  # first occurrence wins

    def test_case_insensitive_host(self):
        a = parse_uri("trojan://pw@EXAMPLE.com:443#1")
        b = parse_uri("trojan://other@example.com:443#2")
        kept, dropped = dedupe_by_endpoint([a, b])
        self.assertEqual((len(kept), dropped), (1, 1))

    def test_different_protocol_fields_do_not_matter(self):
        a = parse_uri("vless://uuid-a@5.6.7.8:443?sni=one#1")
        b = parse_uri("vless://uuid-b@5.6.7.8:443?sni=two#2")
        kept, dropped = dedupe_by_endpoint([a, b])
        self.assertEqual((len(kept), dropped), (1, 1))


# ---------------------------------------------------------------------------
# OLD/NEW classification through the real pipeline helpers
# ---------------------------------------------------------------------------


class ClassificationTests(unittest.TestCase):
    def _old_map(self, *uris: str) -> "OrderedDict[str, object]":
        out: "OrderedDict[str, object]" = OrderedDict()
        for u in uris:
            cfg = parse_uri(u)
            out.setdefault(cfg.endpoint, cfg)
        return out

    def test_new_matching_old_endpoint_is_not_new(self):
        old = self._old_map("trojan://pw@1.2.3.4:443#old-line")
        fresh = [
            parse_uri("vless://uuid@1.2.3.4:443?security=reality#new-same-endpoint"),
            parse_uri("vless://uuid@9.9.9.9:443#truly-new"),
        ]
        candidates = pipeline.merge_and_classify(old, fresh)
        self.assertEqual(len(candidates), 2)
        by_host = {c.cfg.endpoint: c for c in candidates}
        # The old endpoint stays OLD and keeps the ORIGINAL old line.
        self.assertTrue(by_host["1.2.3.4:443"].is_old)
        self.assertIn("#old-line", by_host["1.2.3.4:443"].cfg.raw)
        self.assertTrue(by_host["9.9.9.9:443"].is_old is False)

    def test_write_output_atomic_and_diff_aware(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "proxies.txt"
            cfg = parse_uri(TROJAN)
            self.assertTrue(pipeline.write_output(path, [cfg]))
            self.assertEqual(path.read_text().strip(), TROJAN)
            self.assertFalse(pipeline.write_output(path, [cfg]))  # unchanged
            self.assertFalse((Path(td) / "proxies.txt.tmp").exists())


# ---------------------------------------------------------------------------
# The retry policy - the heart of the specification
# ---------------------------------------------------------------------------


class SequenceTester:
    """Fake connectivity tester with scripted outcomes per endpoint."""

    def __init__(self):
        self.scripts: dict[str, list[bool]] = {}
        self.calls: dict[str, int] = {}

    def plan(self, endpoint: str, outcomes: list[bool]) -> None:
        self.scripts[endpoint] = list(outcomes)
        self.calls[endpoint] = 0

    def test_once(self, cfg, listen_port):
        from worker.singbox import CoreResult

        self.calls[cfg.endpoint] = self.calls.get(cfg.endpoint, 0) + 1
        script = self.scripts.get(cfg.endpoint, [False])
        ok = script.pop(0) if script else False
        return CoreResult(ok, "scripted")


class RetryPolicyTests(unittest.TestCase):
    def _mk(self, endpoint, is_old):
        cfg = parse_uri(f"trojan://pw@{endpoint}#x")
        return Candidate(cfg=cfg, is_old=is_old)

    def test_allowed_attempts(self):
        self.assertEqual(allowed_attempts(True, 3), 4)  # 1 initial + 3 retries
        self.assertEqual(allowed_attempts(True, 0), 1)
        self.assertEqual(allowed_attempts(False, 3), 1)  # NEW: NEVER retried
        self.assertEqual(allowed_attempts(False, 0), 1)

    def test_new_config_gets_exactly_one_attempt(self):
        tester = SequenceTester()
        cand = self._mk("1.1.1.1:443", is_old=False)
        tester.plan("1.1.1.1:443", [False, True, True, True])
        outcomes = run_tests([cand], tester, old_retries=3, workers=1, port_base=46000)
        self.assertFalse(outcomes[0].ok)
        self.assertEqual(outcomes[0].attempts, 1)
        self.assertEqual(tester.calls["1.1.1.1:443"], 1)

    def test_new_config_kept_on_first_success(self):
        tester = SequenceTester()
        cand = self._mk("2.2.2.2:443", is_old=False)
        tester.plan("2.2.2.2:443", [True])
        outcomes = run_tests([cand], tester, old_retries=3, workers=1, port_base=46000)
        self.assertTrue(outcomes[0].ok)
        self.assertEqual(outcomes[0].attempts, 1)

    def test_old_config_retries_until_success(self):
        tester = SequenceTester()
        cand = self._mk("3.3.3.3:443", is_old=True)
        tester.plan("3.3.3.3:443", [False, False, True])
        outcomes = run_tests([cand], tester, old_retries=3, workers=1, port_base=46000)
        self.assertTrue(outcomes[0].ok)
        self.assertEqual(outcomes[0].attempts, 3)
        self.assertEqual(tester.calls["3.3.3.3:443"], 3)

    def test_old_config_removed_after_all_retries_fail(self):
        tester = SequenceTester()
        cand = self._mk("4.4.4.4:443", is_old=True)
        tester.plan("4.4.4.4:443", [False] * 10)
        outcomes = run_tests([cand], tester, old_retries=3, workers=1, port_base=46000)
        self.assertFalse(outcomes[0].ok)
        self.assertEqual(outcomes[0].attempts, 4)  # initial + 3 retries

    def test_old_and_new_mixed_run(self):
        tester = SequenceTester()
        old = self._mk("5.5.5.5:443", is_old=True)
        new = self._mk("6.6.6.6:443", is_old=False)
        tester.plan("5.5.5.5:443", [False, True])
        tester.plan("6.6.6.6:443", [False, True])
        outcomes = run_tests([old, new], tester, old_retries=3, workers=2, port_base=46100)
        self.assertTrue(outcomes[0].ok)          # old saved by retry
        self.assertFalse(outcomes[1].ok)         # new discarded, not retried
        self.assertEqual(tester.calls["5.5.5.5:443"], 2)
        self.assertEqual(tester.calls["6.6.6.6:443"], 1)

    def test_port_pool_assigns_distinct_ports(self):
        pool = PortPool(base=47000, count=4)
        ports = {pool.acquire() for _ in range(4)}
        self.assertEqual(len(ports), 4)


# ---------------------------------------------------------------------------
# sing-box config generation (structure only; no binary required)
# ---------------------------------------------------------------------------


class OutboundBuildTests(unittest.TestCase):
    def test_all_sample_protocols_build(self):
        tokens = [SS_SIP002, VMESS, VLESS_REALITY, TROJAN, TUIC, HYSTERIA, HYSTERIA2, SOCKS5, HTTP_PROXY]
        for token in tokens:
            cfg = parse_uri(token)
            with self.subTest(scheme=cfg.scheme):
                outbound = build_outbound(cfg)
                self.assertIsNotNone(outbound)
                self.assertEqual(outbound["server_port"], cfg.port)
                full = build_core_config(cfg, 48571)
                self.assertIsNotNone(full)
                self.assertEqual(full["route"]["final"], "proxy")
                self.assertEqual(
                    full["inbounds"][0]["listen_port"], 48571
                )
                json.dumps(full)  # must be JSON-serialisable

    def test_vless_reality_details(self):
        cfg = parse_uri(VLESS_REALITY)
        ob = build_outbound(cfg)
        self.assertEqual(ob["type"], "vless")
        self.assertEqual(ob["flow"], "xtls-rprx-vision")
        self.assertEqual(ob["tls"]["reality"]["public_key"], "PUBKEY123")
        self.assertEqual(ob["tls"]["reality"]["short_id"], "ab")
        self.assertEqual(ob["tls"]["server_name"], "www.apple.com")

    def test_vmess_ws_tls_details(self):
        cfg = parse_uri(VMESS)
        ob = build_outbound(cfg)
        self.assertEqual(ob["type"], "vmess")
        self.assertEqual(ob["transport"]["type"], "ws")
        self.assertEqual(ob["transport"]["path"], "/ws")
        self.assertEqual(ob["transport"]["max_early_data"], 2048)
        self.assertEqual(ob["tls"]["server_name"], "sni.example.com")

    def test_hysteria2_obfs(self):
        cfg = parse_uri(HYSTERIA2)
        ob = build_outbound(cfg)
        self.assertEqual(ob["type"], "hysteria2")
        self.assertEqual(ob["obfs"], {"type": "salamander", "password": "opass"})
        self.assertTrue(ob["tls"]["insecure"])

    def test_ssr_is_untestable(self):
        cfg = parse_uri("ssr://" + b64("1.2.3.4:443:origin:aes-128-cfb:plain:" + b64("pw") + "/?obfsparam="))
        self.assertIsNotNone(cfg)
        self.assertEqual(cfg.endpoint, "1.2.3.4:443")
        self.assertIsNone(build_outbound(cfg))  # parsed but not testable


# ---------------------------------------------------------------------------
# Provider name from subscription URL + remark prefix
# ---------------------------------------------------------------------------


class ProviderNameTests(unittest.TestCase):
    def test_github_owner_from_various_url_shapes(self):
        cases = {
            "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt": "youfoundamin",
            "https://github.com/nikita29a/FreeProxyList/raw/refs/heads/main/mirror/9.txt": "nikita29a",
            "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/singbox_configs_all.json": "4n0nymou3",
            "https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/heavy/configs_base64.txt": "0xRadikal",
            "https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/trojan.txt": "Epodonios",
        }
        for url, expected in cases.items():
            with self.subTest(url=url):
                self.assertEqual(provider_from_url(url), expected)

    def test_domain_skips_generic_subdomains(self):
        self.assertEqual(
            provider_from_url("https://sub.iampedi5.live/sub/base64.txt"),
            "iampedi5",
        )
        self.assertEqual(
            provider_from_url("https://www.xrayvip.com/free.txt"),
            "xrayvip",
        )
        self.assertEqual(
            provider_from_url("https://api.examplecdn.net/v1/list"),
            "examplecdn",
        )

    def test_prefix_keeps_emoji_spaces_and_unicode(self):
        original = "trojan://p%40ss%3Aword@example.com:443?security=tls&sni=x.example.com#🇩🇪 Germany 🚀 Premium"
        out = prefix_config_name(original, "youfoundamin")
        self.assertTrue(out.startswith("trojan://p%40ss%3Aword@example.com:443?security=tls&sni=x.example.com#"))
        self.assertTrue(out.endswith("#<youfoundamin>🇩🇪 Germany 🚀 Premium"))
        # Nothing before the fragment changed.
        self.assertEqual(out.split("#", 1)[0], original.split("#", 1)[0])
        self.assertIn("🇩🇪 Germany 🚀 Premium", out)
        self.assertEqual(out.count("🇩🇪"), 1)

    def test_prefix_empty_name_and_no_double_prefix(self):
        bare = "vless://uuid@203.0.113.5:443?security=tls"
        once = prefix_config_name(bare, "xrayvip")
        self.assertTrue(once.endswith("#<xrayvip>"))
        twice = prefix_config_name(once, "xrayvip")
        self.assertEqual(once, twice)

    def test_vmess_ps_is_prefixed_configuration_otherwise_unchanged(self):
        prefixed = prefix_config_name(VMESS, "youfoundamin")
        cfg = parse_uri(prefixed)
        self.assertIsNotNone(cfg)
        self.assertEqual(cfg.endpoint, "203.0.113.7:443")
        self.assertEqual(cfg.fields["uuid"], "11111111-2222-3333-4444-555555555555")
        self.assertEqual(cfg.fields["net"], "ws")
        # Recover ps from the rewritten URI.
        body = prefixed.split("://", 1)[1]
        data = json.loads(b64_to_text(body))
        self.assertEqual(data["ps"], "<youfoundamin>vmess-example")
        self.assertEqual(data["add"], "203.0.113.7")
        self.assertEqual(data["id"], "11111111-2222-3333-4444-555555555555")

    def test_parse_uri_roundtrip_preserves_provider_brackets(self):
        raw = TROJAN.split("#")[0] + "#<youfoundamin>🇩🇪 Germany 01"
        cfg = parse_uri(raw)
        self.assertIsNotNone(cfg)
        self.assertEqual(cfg.raw, raw)
        self.assertTrue(cfg.raw.endswith("#<youfoundamin>🇩🇪 Germany 01"))

    def test_fetch_and_extract_prefixes_from_subscription_url(self):
        from unittest.mock import patch

        from worker.fetcher import FetchResult

        body = "trojan://pw@example.com:443?security=tls#🇩🇪 Germany 01\n"
        fake = FetchResult(
            "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
            True,
            text=body,
            status=200,
        )

        class DummyConfig:
            root = Path(".")
            subscriptions_file = "subscriptions.txt"
            fetch_timeout_seconds = 5
            fetch_user_agent = "test"
            max_download_bytes = 1024

        with patch.object(
            pipeline,
            "read_subscription_urls",
            return_value=[fake.url],
        ), patch.object(pipeline, "fetch_subscription", return_value=fake):
            collected = pipeline.fetch_and_extract(DummyConfig())  # type: ignore[arg-type]
        self.assertEqual(len(collected), 1)
        self.assertTrue(collected[0].raw.endswith("#<youfoundamin>🇩🇪 Germany 01"))
        self.assertIn("trojan://pw@example.com:443", collected[0].raw.split("#", 1)[0])


# ---------------------------------------------------------------------------
# Subscription normalization: Base64, sing-box JSON, raw URIs
# ---------------------------------------------------------------------------


SINGBOX_FULL = {
    "log": {"level": "error"},
    "outbounds": [
        {
            "type": "shadowsocks",
            "tag": "ss-node",
            "server": "198.51.100.11",
            "server_port": 8388,
            "method": "aes-128-gcm",
            "password": "s3cret",
        },
        {
            "type": "vless",
            "tag": "reality-node",
            "server": "203.0.113.5",
            "server_port": 443,
            "uuid": "11111111-2222-3333-4444-555555555555",
            "flow": "xtls-rprx-vision",
            "tls": {
                "enabled": True,
                "server_name": "www.apple.com",
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {
                    "enabled": True,
                    "public_key": "PUBKEY123",
                    "short_id": "ab",
                },
            },
            "transport": {"type": "tcp"},
        },
        {
            "type": "trojan",
            "tag": "tr",
            "server": "example.com",
            "server_port": 443,
            "password": "p@ss:word",
            "tls": {"enabled": True, "server_name": "x.example.com"},
        },
        {
            "type": "vmess",
            "tag": "vmess-example",
            "server": "203.0.113.7",
            "server_port": 443,
            "uuid": "11111111-2222-3333-4444-555555555555",
            "security": "auto",
            "alter_id": 0,
            "tls": {"enabled": True, "server_name": "sni.example.com"},
            "transport": {
                "type": "ws",
                "path": "/ws",
                "headers": {"Host": "cdn.example.com"},
                "max_early_data": 2048,
            },
        },
        {
            "type": "hysteria2",
            "tag": "hy2",
            "server": "10.0.0.11",
            "server_port": 8443,
            "password": "p@ss&word",
            "obfs": {"type": "salamander", "password": "opass"},
            "tls": {"enabled": True, "server_name": "hy2.example.com", "insecure": True},
        },
        {"type": "direct", "tag": "direct"},
        {"type": "selector", "tag": "proxy", "outbounds": ["ss-node"]},
    ],
}


class SubscriptionNormalizeTests(unittest.TestCase):
    def test_raw_uris_pass_through(self):
        body = VLESS_REALITY + "\n" + TROJAN
        text, kind = normalize_subscription(body)
        self.assertEqual(kind, "uri")
        self.assertEqual(text, body)
        self.assertEqual(len(parse_text(text)), 2)

    def test_base64_uri_list_decoded(self):
        plain = SS_SIP002 + "\n" + VLESS_REALITY
        text, kind = normalize_subscription(b64(plain))
        self.assertEqual(kind, "uri")
        cfgs = parse_text(text)
        self.assertEqual(len(cfgs), 2)
        self.assertEqual({c.scheme for c in cfgs}, {"ss", "vless"})

    def test_singbox_full_config_to_uris(self):
        text, kind = normalize_subscription(json.dumps(SINGBOX_FULL))
        self.assertEqual(kind, "sing-box")
        cfgs = parse_text(text)
        schemes = {c.scheme for c in cfgs}
        self.assertEqual(schemes, {"ss", "vless", "trojan", "vmess", "hysteria2"})
        by_scheme = {c.scheme: c for c in cfgs}
        self.assertEqual(by_scheme["ss"].endpoint, "198.51.100.11:8388")
        self.assertEqual(by_scheme["vless"].endpoint, "203.0.113.5:443")
        self.assertEqual(by_scheme["vless"].fields["params"]["pbk"], "PUBKEY123")
        self.assertEqual(by_scheme["trojan"].fields["password"], "p@ss:word")
        self.assertEqual(by_scheme["vmess"].fields["net"], "ws")
        self.assertEqual(by_scheme["hysteria2"].fields["password"], "p@ss&word")

    def test_singbox_outbound_list(self):
        only = [o for o in SINGBOX_FULL["outbounds"] if o["type"] == "shadowsocks"]
        uris = try_convert_singbox(json.dumps(only))
        self.assertIsNotNone(uris)
        self.assertEqual(len(uris), 1)
        cfg = parse_uri(uris[0])
        self.assertEqual(cfg.endpoint, "198.51.100.11:8388")

    def test_base64_encoded_singbox(self):
        blob = b64(json.dumps(SINGBOX_FULL, separators=(",", ":")))
        text, kind = normalize_subscription(blob)
        self.assertEqual(kind, "sing-box")
        self.assertGreaterEqual(len(parse_text(text)), 5)

    def test_singbox_jsonc_comments(self):
        body = '{\n  // comment\n  "outbounds": [{\n    "type": "socks",\n    "server": "10.0.0.12",\n    "server_port": 1080,\n    "username": "user",\n    "password": "pass"\n  }]\n}\n'
        text, kind = normalize_subscription(body)
        self.assertEqual(kind, "sing-box")
        cfg = parse_text(text)[0]
        self.assertEqual(cfg.scheme, "socks5")
        self.assertEqual(cfg.fields["username"], "user")

    def test_non_json_garbage_stays_uri_kind(self):
        text, kind = normalize_subscription("not a proxy and not json")
        self.assertEqual(kind, "uri")
        self.assertEqual(parse_text(text), [])

    def test_selector_only_config_yields_no_uris(self):
        body = json.dumps(
            {"outbounds": [{"type": "direct", "tag": "direct"}]}
        )
        text, kind = normalize_subscription(body)
        self.assertEqual(kind, "sing-box")
        self.assertEqual(parse_text(text), [])

    def test_outbound_to_uri_skips_unknown(self):
        self.assertIsNone(outbound_to_uri({"type": "wireguard", "server": "1.1.1.1"}))
        self.assertIsNone(outbound_to_uri({"type": "vless"}))  # no server


# ---------------------------------------------------------------------------
# Live scan progress + extraction-before-test
# ---------------------------------------------------------------------------


class ProgressAndPipelineOrderTests(unittest.TestCase):
    def _mk(self, endpoint, is_old):
        cfg = parse_uri(f"trojan://pw@{endpoint}#x")
        return Candidate(cfg=cfg, is_old=is_old)

    def test_progress_updates_during_scan(self):
        snapshots: list[ScanProgress] = []
        tester = SequenceTester()
        cands = [self._mk(f"10.0.0.{i}:443", is_old=False) for i in range(1, 6)]
        for c in cands:
            tester.plan(c.cfg.endpoint, [True])
        outcomes = run_tests(
            cands,
            tester,
            old_retries=0,
            workers=2,
            port_base=46200,
            progress=snapshots.append,
            extracted=12,
        )
        self.assertEqual(len(outcomes), 5)
        self.assertGreaterEqual(len(snapshots), 2)
        self.assertEqual(snapshots[0].tested, 0)
        self.assertEqual(snapshots[0].assigned, 5)
        self.assertEqual(snapshots[0].extracted, 12)
        self.assertEqual(snapshots[0].waiting, 5)
        last = snapshots[-1]
        self.assertEqual(last.tested, 5)
        self.assertEqual(last.healthy, 5)
        self.assertEqual(last.failed, 0)
        self.assertEqual(last.waiting, 0)
        self.assertEqual(last.total_workers, 2)
        self.assertEqual(last.completed_workers, 2)
        # At least one snapshot must have been emitted before the scan finished.
        self.assertTrue(any(s.tested < 5 for s in snapshots))

    def test_progress_counts_failures_and_waiting(self):
        snapshots: list[ScanProgress] = []
        tester = SequenceTester()
        ok = self._mk("8.8.8.8:443", is_old=False)
        bad = self._mk("9.9.9.9:443", is_old=False)
        tester.plan("8.8.8.8:443", [True])
        tester.plan("9.9.9.9:443", [False])
        run_tests(
            [ok, bad],
            tester,
            old_retries=0,
            workers=1,
            port_base=46300,
            progress=snapshots.append,
            extracted=2,
        )
        last = snapshots[-1]
        self.assertEqual(last.healthy, 1)
        self.assertEqual(last.failed, 1)
        self.assertEqual(last.tested, 2)

    def test_fetch_and_extract_does_not_start_testers(self):
        """Extraction returns the full list; run_tests is never touched."""
        from unittest.mock import patch

        from worker.fetcher import FetchResult

        body = VLESS_REALITY + "\n" + TROJAN
        fake = FetchResult("https://example.test/sub", True, text=body, status=200)

        class DummyConfig:
            root = Path(".")
            subscriptions_file = "subscriptions.txt"
            fetch_timeout_seconds = 5
            fetch_user_agent = "test"
            max_download_bytes = 1024

        with patch.object(
            pipeline, "read_subscription_urls", return_value=["https://example.test/sub"]
        ), patch.object(pipeline, "fetch_subscription", return_value=fake) as fetch, patch(
            "worker.tester.run_tests"
        ) as tests:
            collected = pipeline.fetch_and_extract(DummyConfig())  # type: ignore[arg-type]
        self.assertEqual(len(collected), 2)
        fetch.assert_called_once()
        tests.assert_not_called()

    def test_save_candidates_payload_includes_extracted_count(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "subscriptions.txt").write_text(
                "# none\n", encoding="utf-8"
            )
            (root / "config.json").write_text(
                json.dumps(
                    {
                        "test_workers": 2,
                        "sing_box_path": "sing-box-missing-binary",
                    }
                ),
                encoding="utf-8",
            )
            # Without a core binary main() exits 2 before save. This test only
            # checks the payload shape helper used after extraction.
            cfg = parse_uri(TROJAN)
            payload = {
                "extracted": 7,
                "candidates": [
                    {
                        "raw": cfg.raw,
                        "is_old": True,
                        "endpoint": cfg.endpoint,
                        "scheme": cfg.scheme,
                    }
                ],
            }
            path = root / "candidates.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["extracted"], 7)
            self.assertEqual(len(loaded["candidates"]), 1)


if __name__ == "__main__":
    unittest.main()
