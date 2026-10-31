"""Subscription download with strict fault isolation.

Every failure mode (DNS, timeout, HTTP error, TLS error, malformed body,
oversized body) is caught and reported; the worker continues with the next
subscription instead of aborting the whole update.
"""
from __future__ import annotations

import gzip
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass
class FetchResult:
    url: str
    ok: bool
    text: str = ""
    error: str = ""
    status: int = 0


def fetch_subscription(
    url: str,
    timeout_seconds: int,
    user_agent: str,
    max_bytes: int,
) -> FetchResult:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": "*/*",
            "Accept-Encoding": "gzip",
            "Connection": "close",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as resp:
            status = getattr(resp, "status", 200) or 200
            if status >= 400:
                return FetchResult(url, False, error=f"HTTP {status}", status=status)

            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = resp.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    return FetchResult(
                        url,
                        False,
                        error=f"body larger than {max_bytes} bytes",
                        status=status,
                    )
                chunks.append(chunk)

            data = b"".join(chunks)
            if (resp.headers.get("Content-Encoding") or "").lower() == "gzip":
                try:
                    data = gzip.decompress(data)
                except OSError:
                    return FetchResult(
                        url, False, error="invalid gzip body", status=status
                    )

            text = data.decode("utf-8", errors="replace")
            return FetchResult(url, True, text=text, status=status)

    except urllib.error.HTTPError as exc:
        return FetchResult(url, False, error=f"HTTP {exc.code}", status=exc.code)
    except urllib.error.URLError as exc:
        return FetchResult(url, False, error=f"network error: {exc.reason}")
    except (socket.timeout, TimeoutError):
        return FetchResult(url, False, error="timeout")
    except ssl.SSLError as exc:
        return FetchResult(url, False, error=f"TLS error: {exc}")
    except Exception as exc:  # absolute isolation; one bad URL must not abort
        return FetchResult(url, False, error=f"unexpected error: {exc}")
