#!/usr/bin/env python3
"""
BlindCore Zero-Dependency Python 3 SDK.
Uses only Python standard library modules (urllib, http.client, socket, ssl,
json, hashlib, base64, struct, os).

Covers:
  - BlindCoreClient: HTTP/1.1, HTTPS, automatic HTTP 402 (x402 v2 / L402 / sBTC),
    Blind Homomorphic OLAP (/api/v1/blind/*), BlindJSONB Encrypted NoSQL
    (/api/v1/blind/jsonb/*), SQL (/api/v1/query), and RFC 6455 live WebSockets.
  - BlindSignClient: Zero-knowledge e-signatures and encrypted vault.
  - BlindFeedClient: Signed posts, E2EE DMs, group ACL key rotation, blind dating.
  - BlindMailClient: Transactional mail, magic links, and DNS verification.
"""

from __future__ import annotations

import atexit
import base64
import hashlib
import hmac
import http.client
import json
import multiprocessing
import os
import secrets
import socket
import ssl
import struct
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Union

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _CRYPTO_AESGCM
except Exception:  # pragma: no cover - optional acceleration; pure-stdlib fallback included
    _CRYPTO_AESGCM = None

try:
    import numpy as _np
except Exception:  # pragma: no cover - optional acceleration; pure-stdlib fallback included
    _np = None

WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_FRAME_BYTES = 67108864
READ_ALLOC_CHUNK = 65536
MAX_HEADER_BYTES = 65536
MAX_HEADER_LINE_BYTES = 8192
MAX_HEADER_COUNT = 128
MAX_INTERIM_1XX = 4
MAX_CONSECUTIVE_CONTROL_FRAMES = 64
IPV6_HOST_CHARS = frozenset("0123456789abcdefABCDEF:.%")
_UNSET: Any = object()


def _has_ctl(val: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in val)


def _is_valid_token(val: str) -> bool:
    return bool(val) and all(0x21 <= ord(ch) <= 0x7E for ch in val)


def _normalize_endpoint(endpoint: str) -> tuple[str, int, str, bool]:
    if _has_ctl(endpoint):
        raise ValueError("endpoint must be free of control characters")
    raw = endpoint.strip()
    if not raw:
        raise ValueError("endpoint must be non-empty")
    use_tls = False
    if raw.startswith(("https://", "wss://")):
        use_tls = True
        raw = raw.split("://", 1)[1]
    elif raw.startswith(("http://", "ws://")):
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0]
    if not raw:
        raise ValueError(f"missing host in '{endpoint}'")
    default_port = 443 if use_tls else 80
    if raw.startswith("["):
        end = raw.find("]")
        if end <= 1:
            raise ValueError(f"expected '[ipv6]' or '[ipv6]:port' in '{endpoint}'")
        host = raw[1:end]
        rest = raw[end + 1 :]
        if not host or not all(ch in IPV6_HOST_CHARS for ch in host):
            raise ValueError(f"invalid IPv6 host in '{endpoint}'")
        if not rest:
            port = default_port
            host_header = f"[{host}]"
        elif rest.startswith(":"):
            port_s = rest[1:]
            if not port_s or not port_s.isascii() or not port_s.isdigit():
                raise ValueError(f"invalid TCP port '{port_s}'")
            port = int(port_s)
            host_header = f"[{host}]:{port}"
        else:
            raise ValueError(f"invalid IPv6 endpoint '{endpoint}'")
    else:
        if ":" in raw:
            host, port_s = raw.rsplit(":", 1)
            if not port_s or not port_s.isascii() or not port_s.isdigit():
                raise ValueError(f"invalid TCP port '{port_s}'")
            port = int(port_s)
            host_header = f"{host}:{port}"
        else:
            host = raw
            port = default_port
            host_header = host
        if not host or not all(ch.isascii() and (ch.isalnum() or ch in "-._") for ch in host):
            raise ValueError(f"invalid host in '{endpoint}'")
    if port <= 0 or port > 65535:
        raise ValueError(f"invalid TCP port {port}")
    return host, port, host_header, use_tls


def _send_masked_ws_frame(sock: socket.socket, opcode: int, payload: bytes) -> None:
    mask = os.urandom(4) or b"\xa5\x5a\xa5\x5a"
    if mask == b"\x00\x00\x00\x00":
        mask = b"\xa5\x5a\xa5\x5a"
    n = len(payload)
    hdr = bytearray([0x80 | (opcode & 0x0F)])
    if n <= 125:
        hdr.append(0x80 | n)
    elif n <= 65535:
        hdr.extend(b"\xfe" + struct.pack("!H", n))
    else:
        hdr.extend(b"\xff" + struct.pack("!Q", n))
    hdr.extend(mask)
    sock.sendall(bytes(hdr) + bytes(b ^ mask[i & 3] for i, b in enumerate(payload)))


class _HardenedHTTPResponse(http.client.HTTPResponse):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._interim_1xx = 0

    def _read_status(self) -> tuple[str, int, str]:
        version, status, reason = super()._read_status()
        if 100 <= status < 200 and status != 101:
            self._interim_1xx += 1
            if self._interim_1xx > MAX_INTERIM_1XX:
                raise RuntimeError(f"too many HTTP 1xx interim responses (>{MAX_INTERIM_1XX})")
        return version, status, reason

    def begin(self) -> None:
        super().begin()
        te_vals = self.headers.get_all("transfer-encoding") or []
        cl_vals = self.headers.get_all("content-length") or []
        if te_vals and cl_vals:
            raise RuntimeError("HTTP response contains both Transfer-Encoding and Content-Length")
        if te_vals and not self.chunked:
            raise RuntimeError("unsupported Transfer-Encoding without chunked")
        if cl_vals:
            parsed_cls: set[int] = set()
            for raw_cl in cl_vals:
                for part in raw_cl.split(","):
                    s = part.strip()
                    if not s or not s.isascii() or not s.isdigit():
                        raise RuntimeError(f"invalid Content-Length '{raw_cl}'")
                    parsed_cls.add(int(s))
            if len(parsed_cls) != 1:
                raise RuntimeError("conflicting duplicate Content-Length headers")
            cl_len = next(iter(parsed_cls))
            if cl_len > MAX_FRAME_BYTES:
                raise RuntimeError(f"Content-Length {cl_len} exceeds {MAX_FRAME_BYTES} byte limit")
            if self.status not in (204, 304) and not (100 <= self.status < 200):
                self.length = cl_len

    def _read_and_discard_trailer(self) -> None:
        count = 0
        total_bytes = 0
        while True:
            line = self.fp.readline(MAX_HEADER_LINE_BYTES + 1)
            if len(line) > MAX_HEADER_LINE_BYTES:
                raise RuntimeError("HTTP chunked trailer line exceeds limit")
            if not line:
                raise EOFError("unexpected EOF inside HTTP chunked trailers")
            if line in (b"\r\n", b"\n"):
                break
            count += 1
            total_bytes += len(line)
            if count > MAX_HEADER_COUNT or total_bytes > MAX_HEADER_BYTES:
                raise RuntimeError("HTTP chunked trailers exceed safety bounds")


class _HardenedHTTPConnection(http.client.HTTPConnection):
    response_class = _HardenedHTTPResponse


class _HardenedHTTPSConnection(http.client.HTTPSConnection):
    response_class = _HardenedHTTPResponse


class _SocketBufReader:
    def __init__(self, sock: socket.socket, initial: bytes = b"") -> None:
        self._sock = sock
        self._buf = bytearray(initial)

    def read_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            want = min(READ_ALLOC_CHUNK, max(4096, n - len(self._buf)))
            chunk = self._sock.recv(want)
            if not chunk:
                raise EOFError("unexpected socket EOF")
            self._buf.extend(chunk)
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def read_u8_or_eof(self) -> int | None:
        if not self._buf:
            chunk = self._sock.recv(4096)
            if not chunk:
                return None
            self._buf.extend(chunk)
        val = self._buf[0]
        del self._buf[0]
        return val


class PaymentRequiredError(Exception):
    """Raised when an endpoint returns HTTP 402 and no payment handler resolves it."""

    def __init__(self, message: str, challenge: Dict[str, Any]) -> None:
        super().__init__(message)
        self.status = 402
        self.challenge = challenge


class ApiError(RuntimeError):
    """Raised when an endpoint returns a non-2xx HTTP status."""

    def __init__(self, message: str, status: int, body: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.body = body


def pad2(data: Union[bytes, str], min_block: int = 256) -> bytes:
    """Power-of-2 PAD2 length-hiding padding: [u32_be len][payload][zero pad]."""
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    needed = 4 + len(raw)
    size = max(16, min_block)
    if size & (size - 1) != 0:
        size = 1 << (size - 1).bit_length()
    while size < needed:
        size *= 2
    header = len(raw).to_bytes(4, "big")
    return header + raw + bytes(size - needed)


def unpad2(padded: bytes) -> bytes:
    """Removes PAD2 length-hiding padding."""
    if len(padded) < 4:
        raise ValueError("Invalid PAD2 buffer: too short.")
    orig_len = int.from_bytes(padded[:4], "big")
    if 4 + orig_len > len(padded):
        raise ValueError("Invalid PAD2 buffer: length exceeds buffer.")
    return padded[4 : 4 + orig_len]


def sha256_hex(data: Union[bytes, str]) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    return hashlib.sha256(raw).hexdigest()


def to_base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def from_base64url(text: str) -> bytes:
    pad = "=" * ((4 - (len(text) % 4)) % 4)
    return base64.urlsafe_b64decode((text + pad).encode("ascii"))


def _parse_payment_challenge(headers: Dict[str, str], body: Any) -> Dict[str, Any]:
    lower = {k.lower(): v for k, v in headers.items()}
    www_auth = lower.get("www-authenticate", "")
    pay_req = lower.get("payment-required") or lower.get("x-payment-required", "")
    stacks_pay_req = lower.get("x-stacks-payment-required", "")
    body_dict = body if isinstance(body, dict) else {}
    extensions = body_dict.get("extensions") if isinstance(body_dict.get("extensions"), dict) else {}
    l402_ext = extensions.get("lightning_l402") if isinstance(extensions.get("lightning_l402"), dict) else {}
    stacks_ext = extensions.get("stacks_sbtc") if isinstance(extensions.get("stacks_sbtc"), dict) else {}

    protocols: List[str] = []
    if pay_req or body_dict.get("x402Version") or "x402" in www_auth.lower():
        protocols.append("x402")
    if (
        "l402" in www_auth.lower()
        or body_dict.get("macaroon")
        or body_dict.get("invoice")
        or bool(l402_ext.get("enabled"))
    ):
        protocols.append("L402")
    if (
        stacks_pay_req
        or "sbtc" in www_auth.lower()
        or body_dict.get("sbtcAddress")
        or body_dict.get("sbtc")
        or bool(stacks_ext)
    ):
        protocols.append("sBTC")
    return {
        "status": 402,
        "protocols": protocols,
        "www_authenticate": www_auth,
        "payment_required": pay_req,
        "x_payment_required": pay_req,
        "stacks_payment_required": stacks_pay_req,
        "body": body,
    }


class BlindCoreClient:
    """Unified zero-dependency BlindCore HTTP/HTTPS/WS + HTTP 402 client."""

    def __init__(
        self,
        base_url: str = "https://api.blindlabs.ai",
        token: Optional[str] = None,
        timeout: float = 30.0,
        on_payment_required: Optional[
            Callable[[Dict[str, Any], Dict[str, Any]], Optional[Dict[str, str]]]
        ] = None,
        ssl_context: Optional[ssl.SSLContext] = None,
        keep_alive: bool = True,
    ) -> None:
        if token is not None:
            if not isinstance(token, str) or not _is_valid_token(token):
                raise ValueError(
                    "BlindCoreClient refuses empty, whitespace, control, or non-ASCII bearer token"
                )
        self._host, self._port, self._host_header, self._use_tls = _normalize_endpoint(base_url)
        scheme = "https" if self._use_tls else "http"
        trimmed = base_url.strip().rstrip("/")
        if trimmed.startswith(("http://", "https://")):
            self.base_url = trimmed
        else:
            self.base_url = f"{scheme}://{self._host_header}"
        self.token = token
        self._token = token
        self.timeout = float(timeout)
        self._timeout = self.timeout
        self.on_payment_required = on_payment_required
        self._ssl_context = ssl_context
        self._keep_alive = bool(keep_alive)
        self._conn_local = threading.local()
        self._open_conns_lock = threading.Lock()
        self._open_conns: list[http.client.HTTPConnection] = []

    def close(self) -> None:
        """Close any cached keep-alive HTTP connections opened by this client."""
        with self._open_conns_lock:
            conns = list(self._open_conns)
            self._open_conns.clear()
        for conn in conns:
            try:
                conn.close()
            except Exception:
                pass
        if hasattr(self._conn_local, "conn"):
            self._conn_local.conn = None

    def __enter__(self) -> "BlindCoreClient":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    def request(
        self,
        path: str,
        method: str = "GET",
        body: Any = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        url = f"{self.base_url}{path if path.startswith('/') else '/' + path}"
        req_headers: Dict[str, str] = {"Accept": "application/json"}
        if headers:
            req_headers.update(headers)
        if self.token and "Authorization" not in req_headers:
            req_headers["Authorization"] = f"Bearer {self.token}"

        payload: Optional[bytes] = None
        if body is not None:
            req_headers["Content-Type"] = "application/json"
            payload = json.dumps(body).encode("utf-8")

        status, resp_headers, resp_body = self._send(url, method, req_headers, payload)
        if status == 402:
            challenge = _parse_payment_challenge(resp_headers, resp_body)
            if self.on_payment_required is not None:
                extra = self.on_payment_required(
                    challenge, {"url": url, "method": method, "body": body}
                )
                if isinstance(extra, dict) and extra:
                    retry_headers = dict(req_headers)
                    retry_headers.update(extra)
                    status, _, resp_body = self._send(url, method, retry_headers, payload)
                    if 200 <= status < 300:
                        return resp_body
                    raise ApiError(self._err_msg(status, resp_body), status, resp_body)
            raise PaymentRequiredError("HTTP 402 Payment Required", challenge)

        if 200 <= status < 300:
            return resp_body
        raise ApiError(self._err_msg(status, resp_body), status, resp_body)

    def _send(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        payload: Optional[bytes],
    ) -> tuple[int, Dict[str, str], Any]:
        req = urllib.request.Request(url=url, data=payload, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_context) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return resp.status, dict(resp.headers.items()), self._parse_json(raw)
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            return exc.code, dict(exc.headers.items()) if exc.headers else {}, self._parse_json(raw)

    @staticmethod
    def _parse_json(raw: str) -> Any:
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"raw": raw}

    @staticmethod
    def _err_msg(status: int, body: Any) -> str:
        if isinstance(body, dict) and body.get("error"):
            return str(body["error"])
        return f"HTTP {status}"

    def query_jsonb(
        self,
        collection: str,
        filter_expr: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Any:
        payload: Dict[str, Any] = {"collection": collection, "filter": filter_expr or {}}
        if options:
            payload.update(options)
        return self.request("/v1/jsonb/query", method="POST", body=payload)

    def ingest_jsonb(
        self,
        collection: str,
        documents: List[Dict[str, Any]],
        options: Optional[Dict[str, Any]] = None,
    ) -> Any:
        payload: Dict[str, Any] = {"collection": collection, "documents": documents}
        if options:
            payload.update(options)
        return self.request("/v1/jsonb/ingest", method="POST", body=payload)

    def sklearn_mnb(self, payload: Dict[str, Any]) -> Any:
        return self.request("/v1/ml/sklearn-mnb", method="POST", body=payload)

    def __repr__(self) -> str:
        scheme = "https" if self._use_tls else "http"
        return f"BlindCoreClient(endpoint='{scheme}://{self._host_header}', token='<redacted>', timeout={self._timeout!r})"

    def _open_conn(self) -> http.client.HTTPConnection:
        if self._use_tls:
            ctx = self._ssl_context if self._ssl_context is not None else ssl.create_default_context()
            return _HardenedHTTPSConnection(self._host, self._port, timeout=self._timeout, context=ctx)
        return _HardenedHTTPConnection(self._host, self._port, timeout=self._timeout)

    def _headers(self, content_type: str | None = None, auth: bool = True) -> dict[str, str]:
        hdrs: dict[str, str] = {"Host": self._host_header}
        if auth and self._token:
            hdrs["Authorization"] = f"Bearer {self._token}"
        if content_type is not None:
            hdrs["Content-Type"] = content_type
        return hdrs

    def _read_bounded_body(self, resp: http.client.HTTPResponse) -> bytes:
        buf = bytearray()
        while True:
            chunk = resp.read(READ_ALLOC_CHUNK)
            if not chunk:
                break
            if len(buf) + len(chunk) > MAX_FRAME_BYTES:
                raise RuntimeError("HTTP response exceeded 64 MiB limit")
            buf.extend(chunk)
        if not resp.chunked and resp.length:
            raise EOFError("unexpected EOF before HTTP Content-Length satisfied")
        return bytes(buf)

    def request_raw(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        content_type: str | None = None,
        auth: bool = True,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> tuple[int, dict[str, str], bytes]:
        if _has_ctl(path) or not path.startswith("/"):
            raise ValueError("path must begin with '/' and contain no control characters")
        hdrs = self._headers(content_type, auth=auth)
        if extra_headers:
            for k, v in extra_headers.items():
                if not isinstance(k, str) or not isinstance(v, str) or _has_ctl(k) or _has_ctl(v):
                    raise ValueError("extra_headers keys and values must be strings without control characters")
                hdrs[k] = v
        if not self._keep_alive:
            conn = self._open_conn()
            try:
                conn.request(method, path, body=body, headers=hdrs)
                resp = conn.getresponse()
                resp_hdrs = {k.lower(): v for k, v in resp.getheaders()}
                data = self._read_bounded_body(resp)
                return resp.status, resp_hdrs, data
            finally:
                conn.close()

        hdrs.setdefault("Connection", "keep-alive")
        for attempt in range(2):
            conn = getattr(self._conn_local, "conn", None)
            reused = conn is not None
            if conn is None:
                conn = self._open_conn()
                self._conn_local.conn = conn
                with self._open_conns_lock:
                    self._open_conns.append(conn)
            try:
                conn.request(method, path, body=body, headers=hdrs)
                resp = conn.getresponse()
                resp_hdrs = {k.lower(): v for k, v in resp.getheaders()}
                data = self._read_bounded_body(resp)
                if resp.will_close or resp_hdrs.get("connection", "").lower() == "close":
                    self._discard_thread_conn(conn)
                return resp.status, resp_hdrs, data
            except (
                http.client.RemoteDisconnected,
                http.client.BadStatusLine,
                http.client.CannotSendRequest,
                http.client.ResponseNotReady,
                BrokenPipeError,
                ConnectionResetError,
                EOFError,
            ):
                self._discard_thread_conn(conn)
                if reused and attempt == 0:
                    continue
                raise
            except Exception:
                self._discard_thread_conn(conn)
                raise
        raise RuntimeError("unreachable HTTP request state")

    def _discard_thread_conn(self, conn: http.client.HTTPConnection) -> None:
        if getattr(self._conn_local, "conn", None) is conn:
            self._conn_local.conn = None
        try:
            conn.close()
        except Exception:
            pass
        with self._open_conns_lock:
            try:
                self._open_conns.remove(conn)
            except ValueError:
                pass

    def _request_bytes_with_402(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        content_type: str | None = None,
        auth: bool = True,
        body_for_hook: Any = None,
    ) -> bytes:
        status, resp_hdrs, data = self.request_raw(
            method, path, body=body, content_type=content_type, auth=auth
        )
        if status == 402:
            parsed = self._parse_json(data.decode("utf-8", errors="replace"))
            challenge = _parse_payment_challenge(resp_hdrs, parsed)
            if self.on_payment_required is not None:
                url = f"{self.base_url}{path}"
                extra = self.on_payment_required(
                    challenge, {"url": url, "method": method, "body": body_for_hook}
                )
                if isinstance(extra, dict) and extra:
                    status, _, data = self.request_raw(
                        method,
                        path,
                        body=body,
                        content_type=content_type,
                        auth=auth,
                        extra_headers=extra,
                    )
                    if 200 <= status < 300:
                        return data
                    retry_parsed = self._parse_json(data.decode("utf-8", errors="replace"))
                    raise ApiError(self._err_msg(status, retry_parsed), status, retry_parsed)
            raise PaymentRequiredError("HTTP 402 Payment Required", challenge)
        if 200 <= status < 300:
            return data
        parsed = self._parse_json(data.decode("utf-8", errors="replace"))
        raise ApiError(self._err_msg(status, parsed), status, parsed)

    def _post_bytes(
        self,
        path: str,
        body: bytes,
        content_type: str,
        body_for_hook: Any = None,
    ) -> bytes:
        return self._request_bytes_with_402(
            "POST",
            path,
            body=body,
            content_type=content_type,
            auth=True,
            body_for_hook=body_for_hook if body_for_hook is not None else body,
        )

    def get_json(self, path: str, auth: bool = True) -> Any:
        data = self._request_bytes_with_402("GET", path, body=None, content_type=None, auth=auth)
        return json.loads(data.decode("utf-8"))

    def post_json(self, path: str, payload: dict[str, Any]) -> Any:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        data = self._post_bytes(path, encoded, "application/json", body_for_hook=payload)
        return json.loads(data.decode("utf-8"))

    def create_blind_table(
        self,
        table: str,
        columns: list[dict[str, str] | tuple[str, str]],
    ) -> dict[str, Any]:
        """Create a Blind Homomorphic OLAP table via POST /api/v1/blind/table."""
        tbl = table.strip() if isinstance(table, str) else ""
        if not tbl or _has_ctl(tbl):
            raise ValueError("table must be a non-empty string without control characters")
        if not isinstance(columns, list) or not columns:
            raise ValueError("columns must be a non-empty list")
        norm_cols: list[dict[str, str]] = []
        for item in columns:
            if isinstance(item, dict):
                name = str(item.get("name", "")).strip()
                kind = str(item.get("kind", "")).strip()
            elif isinstance(item, (tuple, list)) and len(item) == 2:
                name = str(item[0]).strip()
                kind = str(item[1]).strip()
            else:
                raise ValueError("each column must be a {'name': ..., 'kind': ...} dict or (name, kind) tuple")
            if not name or not kind or _has_ctl(name) or _has_ctl(kind):
                raise ValueError("column name and kind must be non-empty strings without control characters")
            norm_cols.append({"name": name, "kind": kind})
        return self.post_json("/api/v1/blind/table", {"table": tbl, "columns": norm_cols})

    def ingest_blind(
        self,
        table: str,
        rows: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Ingest encrypted or server-sealed rows into a Blind OLAP table via POST /api/v1/blind/ingest."""
        tbl = table.strip() if isinstance(table, str) else ""
        if not tbl or _has_ctl(tbl):
            raise ValueError("table must be a non-empty string without control characters")
        if not isinstance(rows, list) or not rows or not all(isinstance(r, dict) for r in rows):
            raise ValueError("rows must be a non-empty list of row dicts")
        return self.post_json("/api/v1/blind/ingest", {"table": tbl, "rows": rows})

    def query_blind(
        self,
        table: str,
        op: str,
        column: str | None = None,
        *,
        rhs_column: str | None = None,
        columns: list[str] | None = None,
        weights: list[int] | None = None,
        weight: int | None = None,
        where: dict[str, Any] | None = None,
        threshold_decrypt: tuple[int, int] | dict[str, int] | None = None,
        decrypt_range: bool | None = None,
        ghost_root_probe: int | str | None = None,
    ) -> dict[str, Any]:
        """Execute a Blind Homomorphic OLAP query via POST /api/v1/blind/query."""
        tbl = table.strip() if isinstance(table, str) else ""
        if not tbl or _has_ctl(tbl):
            raise ValueError("table must be a non-empty string without control characters")
        op_s = op.strip().upper() if isinstance(op, str) else ""
        if not op_s or _has_ctl(op_s):
            raise ValueError("op must be a non-empty string without control characters")
        if column is None and not columns:
            raise ValueError("query_blind requires 'column' or 'columns'")

        payload: dict[str, Any] = {"table": tbl, "op": op_s}
        if column is not None:
            col_s = column.strip()
            if not col_s or _has_ctl(col_s):
                raise ValueError("column must be non-empty without control characters")
            payload["column"] = col_s
        if rhs_column is not None:
            rhs_s = rhs_column.strip()
            if not rhs_s or _has_ctl(rhs_s):
                raise ValueError("rhs_column must be non-empty without control characters")
            payload["rhs_column"] = rhs_s
        if columns is not None:
            if not isinstance(columns, list) or not columns:
                raise ValueError("columns must be a non-empty list of column names")
            norm_list: list[str] = []
            for cn in columns:
                cn_s = str(cn).strip()
                if not cn_s or _has_ctl(cn_s):
                    raise ValueError("each entry in columns must be non-empty without control characters")
                norm_list.append(cn_s)
            payload["columns"] = norm_list
        if weights is not None:
            payload["weights"] = [int(w) for w in weights]
        if weight is not None:
            payload["weight"] = int(weight)
        if where is not None:
            if not isinstance(where, dict) or "column" not in where:
                raise ValueError("where must be a {'column': ..., 'eq': ...} or {'column': ..., 'eq_token_hex': ...} dict")
            wcol = str(where["column"]).strip()
            if not wcol or _has_ctl(wcol):
                raise ValueError("where['column'] must be non-empty without control characters")
            has_eq = "eq" in where and where["eq"] is not None
            has_tok = "eq_token_hex" in where and where["eq_token_hex"] is not None
            if has_eq == has_tok:
                raise ValueError("where must specify exactly one of 'eq' or 'eq_token_hex'")
            if has_tok:
                tok_s = str(where["eq_token_hex"]).strip()
                if len(tok_s) != 64 or _has_ctl(tok_s):
                    raise ValueError("where['eq_token_hex'] must be a 64-character hex string")
                try:
                    bytes.fromhex(tok_s)
                except ValueError as exc:
                    raise ValueError("where['eq_token_hex'] must be valid hex") from exc
                payload["where"] = {"column": wcol, "eq_token_hex": tok_s}
            else:
                payload["where"] = {"column": wcol, "eq": int(where["eq"])}
        if threshold_decrypt is not None:
            if isinstance(threshold_decrypt, (tuple, list)) and len(threshold_decrypt) == 2:
                t_val, n_val = int(threshold_decrypt[0]), int(threshold_decrypt[1])
            elif isinstance(threshold_decrypt, dict) and "t" in threshold_decrypt and "n" in threshold_decrypt:
                t_val, n_val = int(threshold_decrypt["t"]), int(threshold_decrypt["n"])
            else:
                raise ValueError("threshold_decrypt must be a (t, n) tuple or {'t': t, 'n': n} dict")
            if t_val < 1 or n_val < t_val:
                raise ValueError("threshold_decrypt requires 1 <= t <= n")
            payload["threshold_decrypt"] = {"t": t_val, "n": n_val}
        if decrypt_range is not None:
            payload["decrypt_range"] = bool(decrypt_range)
        if ghost_root_probe is not None:
            payload["ghost_root_probe"] = str(ghost_root_probe)
        return self.post_json("/api/v1/blind/query", payload)

    def create_blind_jsonb_table(
        self,
        table: str,
        k_tok: int = 8,
        k_num: int = 8,
        *,
        allow_low_entropy_tokens: bool = False,
        k_min_tkms: int = 16,
    ) -> dict[str, Any]:
        """Create a BlindJSONB encrypted NoSQL collection via POST /api/v1/blind/jsonb/table."""
        tbl = table.strip() if isinstance(table, str) else ""
        if not tbl or _has_ctl(tbl):
            raise ValueError("table must be a non-empty string without control characters")
        kt = int(k_tok)
        kn = int(k_num)
        km = int(k_min_tkms)
        if kt not in (4, 8, 16, 32):
            raise ValueError("k_tok must be one of 4, 8, 16, 32")
        if kn not in (4, 8, 16):
            raise ValueError("k_num must be one of 4, 8, 16")
        if km < 1 or km > 65535:
            raise ValueError("k_min_tkms must be in 1..=65535")
        payload: dict[str, Any] = {
            "table": tbl,
            "k_tok": kt,
            "k_num": kn,
            "allow_low_entropy_tokens": bool(allow_low_entropy_tokens),
            "k_min_tkms": km,
        }
        return self.post_json("/api/v1/blind/jsonb/table", payload)

    def ingest_blind_jsonb(
        self,
        table: str,
        rows: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Ingest encrypted JSON documents, UPSERTs, or TOMBSTONEs via POST /api/v1/blind/jsonb/ingest."""
        tbl = table.strip() if isinstance(table, str) else ""
        if not tbl or _has_ctl(tbl):
            raise ValueError("table must be a non-empty string without control characters")
        if not isinstance(rows, list) or not rows or not all(isinstance(r, dict) for r in rows):
            raise ValueError("rows must be a non-empty list of row dicts")
        return self.post_json("/api/v1/blind/jsonb/ingest", {"table": tbl, "rows": rows})

    def query_blind_jsonb(
        self,
        table: str,
        op: str,
        *,
        path: str | None = None,
        path_tok_hex: str | None = None,
        value: Any = _UNSET,
        is_array_elem: bool | None = None,
        filter: dict[str, Any] | None = None,
        containment_token_hex: str | None = None,
        contains_tokens_hex: list[str] | None = None,
        entity_id: str | None = None,
        doc_id: str | None = None,
        doc_id_tok_hex: str | None = None,
        weights: list[int] | None = None,
        weight: int | None = None,
        train_classes: list[dict[str, Any]] | None = None,
        vocab_paths: list[str] | None = None,
        vocab_tokens_hex: list[str] | None = None,
        alpha: float | None = None,
        weight_scale: int | None = None,
        score_cohorts: list[dict[str, Any]] | None = None,
        threshold_decrypt: tuple[int, int] | dict[str, int] | None = None,
    ) -> dict[str, Any]:
        """Execute a BlindJSONB query (LATEST, CONTAINS, SUM, WEIGHTED_SUM, SKLEARN_MNB) via POST /api/v1/blind/jsonb/query."""
        tbl = table.strip() if isinstance(table, str) else ""
        if not tbl or _has_ctl(tbl):
            raise ValueError("table must be a non-empty string without control characters")
        op_s = op.strip().upper() if isinstance(op, str) else ""
        if not op_s or _has_ctl(op_s):
            raise ValueError("op must be a non-empty string without control characters")

        payload: dict[str, Any] = {"table": tbl, "op": op_s}
        for key, raw_val in (
            ("path", path),
            ("path_tok_hex", path_tok_hex),
            ("containment_token_hex", containment_token_hex),
            ("entity_id", entity_id),
            ("doc_id", doc_id),
            ("doc_id_tok_hex", doc_id_tok_hex),
        ):
            if raw_val is not None:
                val_s = raw_val.strip()
                if not val_s or _has_ctl(val_s):
                    raise ValueError(f"{key} must be non-empty without control characters")
                payload[key] = val_s

        if value is not _UNSET:
            payload["value"] = value
        if is_array_elem is not None:
            payload["is_array_elem"] = bool(is_array_elem)
        if filter is not None:
            if not isinstance(filter, dict) or "path" not in filter or "value" not in filter:
                raise ValueError("filter must be a {'path': ..., 'value': ...} dict")
            fpath = str(filter["path"]).strip()
            if not fpath or _has_ctl(fpath):
                raise ValueError("filter['path'] must be non-empty without control characters")
            fobj: dict[str, Any] = {"path": fpath, "value": filter["value"]}
            if "is_array_elem" in filter and filter["is_array_elem"] is not None:
                fobj["is_array_elem"] = bool(filter["is_array_elem"])
            payload["filter"] = fobj
        if contains_tokens_hex is not None:
            if not isinstance(contains_tokens_hex, list) or not contains_tokens_hex:
                raise ValueError("contains_tokens_hex must be a non-empty list of hex strings")
            norm_toks: list[str] = []
            for tok in contains_tokens_hex:
                tok_s = str(tok).strip()
                if not tok_s or _has_ctl(tok_s):
                    raise ValueError("each entry in contains_tokens_hex must be non-empty without control characters")
                norm_toks.append(tok_s)
            payload["contains_tokens_hex"] = norm_toks
        if weights is not None:
            payload["weights"] = [int(w) for w in weights]
        if weight is not None:
            payload["weight"] = int(weight)
        if train_classes is not None:
            if not isinstance(train_classes, list) or not all(isinstance(c, dict) for c in train_classes):
                raise ValueError("train_classes must be a list of cohort dicts")
            payload["train_classes"] = train_classes
        if vocab_paths is not None:
            if not isinstance(vocab_paths, list) or not vocab_paths:
                raise ValueError("vocab_paths must be a non-empty list of JSON pointer paths")
            norm_vp: list[str] = []
            for vp in vocab_paths:
                vp_s = str(vp).strip()
                if not vp_s or _has_ctl(vp_s):
                    raise ValueError("each entry in vocab_paths must be non-empty without control characters")
                norm_vp.append(vp_s)
            payload["vocab_paths"] = norm_vp
        if vocab_tokens_hex is not None:
            if not isinstance(vocab_tokens_hex, list) or not vocab_tokens_hex:
                raise ValueError("vocab_tokens_hex must be a non-empty list of hex strings")
            norm_vt: list[str] = []
            for vt in vocab_tokens_hex:
                vt_s = str(vt).strip()
                if not vt_s or _has_ctl(vt_s):
                    raise ValueError("each entry in vocab_tokens_hex must be non-empty without control characters")
                norm_vt.append(vt_s)
            payload["vocab_tokens_hex"] = norm_vt
        if alpha is not None:
            payload["alpha"] = float(alpha)
        if weight_scale is not None:
            payload["weight_scale"] = int(weight_scale)
        if score_cohorts is not None:
            if not isinstance(score_cohorts, list) or not all(isinstance(c, dict) for c in score_cohorts):
                raise ValueError("score_cohorts must be a list of cohort dicts")
            payload["score_cohorts"] = score_cohorts
        if threshold_decrypt is not None:
            if isinstance(threshold_decrypt, (tuple, list)) and len(threshold_decrypt) == 2:
                t_val, n_val = int(threshold_decrypt[0]), int(threshold_decrypt[1])
            elif isinstance(threshold_decrypt, dict) and "t" in threshold_decrypt and "n" in threshold_decrypt:
                t_val, n_val = int(threshold_decrypt["t"]), int(threshold_decrypt["n"])
            else:
                raise ValueError("threshold_decrypt must be a (t, n) tuple or {'t': t, 'n': n} dict")
            if t_val < 1 or n_val < t_val:
                raise ValueError("threshold_decrypt requires 1 <= t <= n")
            payload["threshold_decrypt"] = {"t": t_val, "n": n_val}
        return self.post_json("/api/v1/blind/jsonb/query", payload)

    def query_json(self, sql: str) -> Any:
        q = sql.strip()
        if not q:
            raise ValueError("SQL query must not be empty")
        return json.loads(
            self._post_bytes(
                "/api/v1/query?format=json",
                q.encode("utf-8"),
                "text/plain; charset=utf-8",
                body_for_hook=q,
            ).decode("utf-8")
        )

    def query_ndjson_stream(self, sql: str) -> Iterator[Any]:
        q = sql.strip()
        if not q:
            raise ValueError("SQL query must not be empty")
        conn = self._open_conn()
        try:
            conn.request(
                "POST",
                "/api/v1/query?format=ndjson",
                body=q.encode("utf-8"),
                headers=self._headers("text/plain; charset=utf-8", auth=True),
            )
            resp = conn.getresponse()
            if resp.status < 200 or resp.status >= 300:
                raise RuntimeError(
                    f"HTTP {resp.status} {resp.reason}: {resp.read(65536).decode('utf-8', 'replace').strip()}"
                )
            while True:
                line = resp.readline(MAX_FRAME_BYTES + 1)
                if not line:
                    break
                if len(line) > MAX_FRAME_BYTES or (len(line) == MAX_FRAME_BYTES and not line.endswith(b"\n")):
                    raise RuntimeError(f"NDJSON line exceeded {MAX_FRAME_BYTES} byte limit")
                text = line.decode("utf-8").strip()
                if text:
                    yield json.loads(text)
            if not resp.chunked and resp.length:
                raise EOFError("unexpected EOF in NDJSON stream")
        finally:
            conn.close()

    def ws_live_frames(self, topic: str | None = None) -> Iterator[bytes]:
        path = "/api/ws/live"
        if topic is not None and topic.strip():
            clean_topic = topic.strip()
            if _has_ctl(clean_topic):
                raise ValueError("topic contains control characters")
            path = f"/api/ws/live?topic={urllib.parse.quote(clean_topic, safe='')}"
        sec_key = base64.b64encode(os.urandom(16)).decode("ascii")
        expected_accept = base64.b64encode(hashlib.sha1(sec_key.encode("ascii") + WS_GUID).digest()).decode("ascii")
        raw_sock = socket.create_connection((self._host, self._port), timeout=self._timeout)
        if self._use_tls:
            ctx = self._ssl_context if self._ssl_context is not None else ssl.create_default_context()
            sock: socket.socket = ctx.wrap_socket(raw_sock, server_hostname=self._host)
        else:
            sock = raw_sock
        close_sent = False
        try:
            auth_hdr = f"Authorization: Bearer {self._token}\r\n" if self._token else ""
            req = (
                f"GET {path} HTTP/1.1\r\nHost: {self._host_header}\r\n{auth_hdr}"
                f"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {sec_key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            )
            sock.sendall(req.encode("ascii"))
            head_buf = bytearray()
            while b"\r\n\r\n" not in head_buf:
                chunk = sock.recv(4096)
                if not chunk or len(head_buf) + len(chunk) > MAX_HEADER_BYTES:
                    raise RuntimeError("WebSocket 101 handshake failed or exceeded 64 KiB")
                head_buf.extend(chunk)
            sep = head_buf.index(b"\r\n\r\n")
            head_lines = head_buf[:sep].decode("utf-8").split("\r\n")
            parts = head_lines[0].split(" ", 2)
            if len(parts) < 2 or parts[0] != "HTTP/1.1" or parts[1] != "101":
                raise RuntimeError(f"WebSocket upgrade rejected: {head_lines[0]}")
            if len(head_lines) - 1 > MAX_HEADER_COUNT:
                raise RuntimeError("WebSocket 101 response headers exceed safety bounds")
            hdrs: dict[str, list[str]] = {}
            for ln in head_lines[1:]:
                if ":" not in ln:
                    raise RuntimeError(f"malformed HTTP header line in WebSocket 101 response: '{ln}'")
                k, v = ln.split(":", 1)
                kl = k.strip().lower()
                if not kl:
                    raise RuntimeError("empty HTTP header name in WebSocket 101 response")
                hdrs.setdefault(kl, []).append(v.strip())
            upgrade_ok = any(v.lower() == "websocket" for v in hdrs.get("upgrade", []))
            conn_ok = any(
                tok.strip().lower() == "upgrade"
                for v in hdrs.get("connection", [])
                for tok in v.split(",")
            )
            accept_vals = hdrs.get("sec-websocket-accept", [])
            if not upgrade_ok or not conn_ok or len(accept_vals) != 1 or accept_vals[0] != expected_accept:
                raise RuntimeError("WebSocket 101 Upgrade, Connection, or Sec-WebSocket-Accept verification failed")

            reader = _SocketBufReader(sock, bytes(head_buf[sep + 4 :]))
            frag: bytearray | None = None
            ctrl_frames = 0
            while True:
                b0 = reader.read_u8_or_eof()
                if b0 is None:
                    if frag is not None:
                        raise EOFError("unexpected EOF inside fragmented WebSocket message")
                    break
                b1 = reader.read_exact(1)[0]
                fin, opcode, len7 = (b0 & 0x80) != 0, b0 & 0x0F, b1 & 0x7F
                if (b0 & 0x70) != 0 or (b1 & 0x80) != 0 or (opcode >= 0x8 and (not fin or len7 > 125)):
                    raise RuntimeError("RFC 6455 frame header protocol violation")
                if len7 <= 125:
                    plen = len7
                elif len7 == 126:
                    plen = struct.unpack("!H", reader.read_exact(2))[0]
                else:
                    plen = struct.unpack("!Q", reader.read_exact(8))[0]
                    if (plen >> 63) != 0:
                        raise RuntimeError("RFC 6455 negative 64-bit frame length")
                if plen > MAX_FRAME_BYTES:
                    raise RuntimeError("WebSocket frame exceeds 64 MiB limit")
                if opcode == 0x2:
                    if frag is not None:
                        raise RuntimeError("received nested binary opcode before FIN")
                    payload = reader.read_exact(plen)
                    if fin:
                        ctrl_frames = 0
                        yield payload
                    else:
                        frag = bytearray(payload)
                elif opcode == 0x0:
                    if frag is None or len(frag) + plen > MAX_FRAME_BYTES:
                        raise RuntimeError("invalid or oversized fragmented WebSocket frame")
                    payload = reader.read_exact(plen)
                    frag.extend(payload)
                    if fin:
                        out_msg = bytes(frag)
                        frag = None
                        ctrl_frames = 0
                        yield out_msg
                elif opcode == 0x9:
                    ctrl_frames += 1
                    if ctrl_frames > MAX_CONSECUTIVE_CONTROL_FRAMES:
                        raise RuntimeError(
                            f"too many consecutive WebSocket control frames (>{MAX_CONSECUTIVE_CONTROL_FRAMES})"
                        )
                    payload = reader.read_exact(plen)
                    _send_masked_ws_frame(sock, 0xA, payload)
                elif opcode == 0xA:
                    ctrl_frames += 1
                    if ctrl_frames > MAX_CONSECUTIVE_CONTROL_FRAMES:
                        raise RuntimeError(
                            f"too many consecutive WebSocket control frames (>{MAX_CONSECUTIVE_CONTROL_FRAMES})"
                        )
                    _ = reader.read_exact(plen)
                elif opcode == 0x8:
                    payload = reader.read_exact(plen)
                    _send_masked_ws_frame(sock, 0x8, payload[:2] if len(payload) >= 2 else b"\x03\xe8")
                    close_sent = True
                    break
                else:
                    raise RuntimeError(f"unsupported WebSocket opcode 0x{opcode:X}")
        finally:
            if not close_sent:
                try:
                    _send_masked_ws_frame(sock, 0x8, b"\x03\xe8")
                except OSError:
                    pass
            sock.close()


class BlindSignClient:
    """BlindSign Client: Zero-Knowledge e-Signatures & Encrypted Vault."""

    def __init__(self, core: BlindCoreClient) -> None:
        self.core = core

    def create_envelope(
        self,
        *,
        title: str,
        digest_sha256: str,
        encrypted_blob: Dict[str, Any],
        file_name: str = "document.bin",
        mime_type: str = "application/octet-stream",
        signers: Optional[List[str]] = None,
        signature: Optional[str] = None,
        key_base64url: str = "",
        app_origin: str = "https://blindlabs.ai/sign",
    ) -> Dict[str, Any]:
        resp = self.core.request(
            "/v1/sign/envelopes",
            method="POST",
            body={
                "title": title,
                "file_name": file_name,
                "mime_type": mime_type,
                "digest_sha256": digest_sha256,
                "signers": signers or [],
                "signature": signature,
                "encrypted_blob": encrypted_blob,
            },
        )
        envelope_id = ""
        if isinstance(resp, dict):
            envelope_id = str(resp.get("envelope_id") or resp.get("id") or "")
        invite_link = (
            f"{app_origin.rstrip('/')}/#env={urllib.parse.quote(envelope_id)}&k={key_base64url}"
            if key_base64url
            else f"{app_origin.rstrip('/')}/#env={urllib.parse.quote(envelope_id)}"
        )
        return {
            "envelope_id": envelope_id,
            "invite_link": invite_link,
            "response": resp,
        }

    def countersign_envelope(
        self, *, envelope_id: str, digest_sha256: str, signature: str, signer_id: str
    ) -> Any:
        return self.core.request(
            f"/v1/sign/envelopes/{urllib.parse.quote(envelope_id)}/countersign",
            method="POST",
            body={
                "signer_id": signer_id,
                "digest_sha256": digest_sha256,
                "signature": signature,
            },
        )

    def shred_envelope(self, envelope_id: str, reason: str = "user_requested") -> Any:
        return self.core.request(
            f"/v1/sign/envelopes/{urllib.parse.quote(envelope_id)}",
            method="DELETE",
            body={"reason": reason},
        )

    def store_vault_item(
        self,
        *,
        label: str,
        encrypted_blob: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Any:
        return self.core.request(
            "/v1/vault/items",
            method="POST",
            body={
                "label": label,
                "metadata": metadata or {},
                "encrypted_blob": encrypted_blob,
            },
        )

    def create_temp_share(
        self,
        *,
        item_id: str,
        ttl_seconds: int = 3600,
        max_views: int = 1,
        key_base64url: str = "",
        app_origin: str = "https://blindlabs.ai/sign",
    ) -> Dict[str, Any]:
        resp = self.core.request(
            "/v1/vault/shares",
            method="POST",
            body={
                "item_id": item_id,
                "ttl_seconds": ttl_seconds,
                "max_views": max_views,
            },
        )
        share_id = ""
        if isinstance(resp, dict):
            share_id = str(resp.get("share_id") or resp.get("id") or "")
        share_link = (
            f"{app_origin.rstrip('/')}/#share={urllib.parse.quote(share_id)}&k={key_base64url}"
            if key_base64url
            else f"{app_origin.rstrip('/')}/#share={urllib.parse.quote(share_id)}"
        )
        return {"share_id": share_id, "share_link": share_link, "response": resp}


class BlindFeedClient:
    """BlindFeed Client: Signed Posts, E2EE DMs, Group ACLs, and Blind Dating."""

    def __init__(self, core: BlindCoreClient) -> None:
        self.core = core

    def register_profile(
        self,
        *,
        handle: str,
        display_name: str,
        signing_public_jwk: Dict[str, Any],
        ecdh_public_jwk: Dict[str, Any],
        bio: str = "",
    ) -> Any:
        return self.core.request(
            "/v1/feed/profiles",
            method="POST",
            body={
                "handle": handle,
                "display_name": display_name,
                "signing_public_jwk": signing_public_jwk,
                "ecdh_public_jwk": ecdh_public_jwk,
                "bio": bio,
            },
        )

    def create_signed_post(
        self,
        *,
        author_id: str,
        body: str,
        signature: str,
        created_at: str,
        media_refs: Optional[List[str]] = None,
    ) -> Any:
        return self.core.request(
            "/v1/feed/posts",
            method="POST",
            body={
                "author_id": author_id,
                "body": body,
                "media_refs": media_refs or [],
                "created_at": created_at,
                "signature": signature,
            },
        )

    def send_encrypted_dm(
        self,
        *,
        sender_id: str,
        recipient_id: str,
        encrypted_dm: Dict[str, Any],
    ) -> Any:
        return self.core.request(
            "/v1/feed/dms",
            method="POST",
            body={
                "sender_id": sender_id,
                "recipient_id": recipient_id,
                "encrypted_dm": encrypted_dm,
            },
        )

    def create_group(
        self,
        *,
        name: str,
        creator_id: str,
        wrapped_member_keys: Optional[Dict[str, Any]] = None,
    ) -> Any:
        return self.core.request(
            "/v1/feed/groups",
            method="POST",
            body={
                "name": name,
                "creator_id": creator_id,
                "wrapped_member_keys": wrapped_member_keys or {},
            },
        )

    def add_group_member(
        self,
        *,
        group_id: str,
        member_id: str,
        wrapped_group_key: Dict[str, Any],
        role: str = "member",
    ) -> Any:
        return self.core.request(
            f"/v1/feed/groups/{urllib.parse.quote(group_id)}/members",
            method="POST",
            body={
                "member_id": member_id,
                "wrapped_group_key": wrapped_group_key,
                "role": role,
            },
        )

    def remove_group_member_and_rotate(
        self,
        *,
        group_id: str,
        remove_member_id: str,
        rotated_wrapped_keys: Dict[str, Any],
    ) -> Any:
        return self.core.request(
            f"/v1/feed/groups/{urllib.parse.quote(group_id)}/rotate",
            method="POST",
            body={
                "remove_member_id": remove_member_id,
                "rotated_wrapped_keys": rotated_wrapped_keys,
            },
        )

    def grant_temp_group_access(
        self,
        *,
        group_id: str,
        guest_id: str,
        wrapped_group_key: Dict[str, Any],
        ttl_seconds: int = 3600,
    ) -> Any:
        return self.core.request(
            f"/v1/feed/groups/{urllib.parse.quote(group_id)}/temp-access",
            method="POST",
            body={
                "guest_id": guest_id,
                "wrapped_group_key": wrapped_group_key,
                "ttl_seconds": ttl_seconds,
            },
        )

    def submit_dating_swipe(
        self,
        *,
        actor_id: str,
        target_id: str,
        direction: str,
        blind_token: Optional[str] = None,
    ) -> Any:
        return self.core.request(
            "/v1/feed/dating/swipe",
            method="POST",
            body={
                "actor_id": actor_id,
                "target_id": target_id,
                "direction": direction,
                "blind_token": blind_token,
            },
        )


class BlindMailClient:
    """BlindMail Client: Transactional Mail, Magic Links, and DNS Verification."""

    def __init__(self, core: BlindCoreClient) -> None:
        self.core = core

    def send_mail(
        self,
        *,
        sender: str,
        to: Union[str, List[str]],
        subject: str,
        body: str,
        encrypted_payload: Optional[Dict[str, Any]] = None,
    ) -> Any:
        return self.core.request(
            "/v1/mail/send",
            method="POST",
            body={
                "from": sender,
                "to": to,
                "subject": subject,
                "body": body,
                "encrypted_payload": encrypted_payload,
            },
        )

    def request_magic_link(self, *, email: str, redirect_url: str) -> Any:
        return self.core.request(
            "/v1/mail/magic-link/request",
            method="POST",
            body={"email": email, "redirect_url": redirect_url},
        )

    def verify_magic_link(self, *, token: str) -> Any:
        return self.core.request(
            "/v1/mail/magic-link/verify",
            method="POST",
            body={"token": token},
        )

    def get_dns_records(self, domain: str) -> Any:
        return self.core.request(
            f"/v1/mail/dns/{urllib.parse.quote(domain)}",
            method="GET",
        )


# ---------------------------------------------------------------------------
# Client-Side Zero-Knowledge Cryptographic Primitives (Mode 2)
# ---------------------------------------------------------------------------

LWE_DIM = 1024
LWE_Q0 = (1 << 127) - 1
LWE_PLAIN_MOD = 890_969_009_638_765_049
PLWE_MAGIC = b"PLWE0001"
PLWE_PROFILE_D0 = 0
PLWE_SEEDED_BYTES = 80
PLWE_EXPANDED_BYTES = 16464
SBLB_MAGIC = b"SBLB0001"
SBLB_BUCKETS = (64, 128, 256, 512, 1024, 2048, 4096)

_CRC32C_TABLE: tuple[int, ...] = tuple(
    (lambda c: [c := ((c >> 1) ^ 0x82F63B78 if (c & 1) else (c >> 1)) for _ in range(8)][-1])(i)
    for i in range(256)
)
_CRC32C_NP_CACHE: Any = None
_PLWE_POOL_LOCK = threading.Lock()
_PLWE_POOL: Any = None
_PLWE_POOL_WORKERS: int = 0
_WORKER_PLWE_KEYS: dict[bytes, "BlindClientPlweKey"] = {}


def _crc32c_pure(data: bytes | memoryview, init_crc: int = 0xFFFFFFFF) -> int:
    crc = init_crc
    tbl = _CRC32C_TABLE
    for byte in data:
        crc = tbl[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc


def _gf2_mat_vec(mat: list[int], vec: int) -> int:
    out = 0
    row_i = 0
    while vec:
        if vec & 1:
            out ^= mat[row_i]
        vec >>= 1
        row_i += 1
    return out


def _gf2_mat_sq(mat: list[int]) -> list[int]:
    return [_gf2_mat_vec(mat, col) for col in mat]


def _get_crc32c_np_tables() -> Any:
    global _CRC32C_NP_CACHE
    if _CRC32C_NP_CACHE is not None:
        return _CRC32C_NP_CACHE
    tbl_np = _np.array(_CRC32C_TABLE, dtype=_np.uint32)
    # Linear operator L_1 for advancing CRC-32C by 1 zero byte in reflected form.
    tbl = _CRC32C_TABLE
    mat = [tbl[(1 << bit) & 0xFF] ^ ((1 << bit) >> 8) for bit in range(32)]
    # Square 4 times to obtain L_16 (16-byte lane stride).
    for _ in range(4):
        mat = _gf2_mat_sq(mat)
    stride_tables: list[tuple[Any, Any, Any, Any]] = []
    cur = mat
    for _ in range(16):  # Strides from 16 B up to 512 KiB
        t0 = _np.array([_gf2_mat_vec(cur, b) for b in range(256)], dtype=_np.uint32)
        t1 = _np.array([_gf2_mat_vec(cur, b << 8) for b in range(256)], dtype=_np.uint32)
        t2 = _np.array([_gf2_mat_vec(cur, b << 16) for b in range(256)], dtype=_np.uint32)
        t3 = _np.array([_gf2_mat_vec(cur, b << 24) for b in range(256)], dtype=_np.uint32)
        stride_tables.append((t0, t1, t2, t3))
        cur = _gf2_mat_sq(cur)
    _CRC32C_NP_CACHE = (tbl_np, stride_tables)
    return _CRC32C_NP_CACHE


def crc32c(data: bytes) -> int:
    """Compute Castagnoli CRC-32C (polynomial 0x82F63B78)."""
    if _np is None or len(data) < 256:
        return _crc32c_pure(data) ^ 0xFFFFFFFF
    tbl_np, stride_tables = _get_crc32c_np_tables()
    crc = 0xFFFFFFFF
    pos = 0
    total = len(data)
    u32_8 = _np.uint32(8)
    u32_16 = _np.uint32(16)
    u32_24 = _np.uint32(24)
    u32_ff = _np.uint32(0xFF)
    while total - pos >= 256:
        k_pow = min(((total - pos) // 16).bit_length() - 1, len(stride_tables))
        m = 1 << k_pow
        span = m * 16
        blocks = _np.frombuffer(data, dtype=_np.uint8, count=span, offset=pos).reshape(m, 16)
        c = _np.zeros(m, dtype=_np.uint32)
        c[0] = _np.uint32(crc)
        for j in range(16):
            c = tbl_np[(c ^ blocks[:, j]) & u32_ff] ^ (c >> u32_8)
        for lvl in range(k_pow):
            t0, t1, t2, t3 = stride_tables[lvl]
            left = c[0::2]
            right = c[1::2]
            c = (
                t0[left & u32_ff]
                ^ t1[(left >> u32_8) & u32_ff]
                ^ t2[(left >> u32_16) & u32_ff]
                ^ t3[(left >> u32_24) & u32_ff]
                ^ right
            )
        crc = int(c[0])
        pos += span
    if pos < total:
        crc = _crc32c_pure(memoryview(data)[pos:], crc)
    return crc ^ 0xFFFFFFFF


def _shutdown_plwe_pool() -> None:
    global _PLWE_POOL, _PLWE_POOL_WORKERS
    pool = _PLWE_POOL
    _PLWE_POOL = None
    _PLWE_POOL_WORKERS = 0
    if pool is not None:
        try:
            pool.terminate()
            pool.join()
        except Exception:
            pass


atexit.register(_shutdown_plwe_pool)


def _get_plwe_pool(workers: int) -> Any:
    global _PLWE_POOL, _PLWE_POOL_WORKERS
    with _PLWE_POOL_LOCK:
        if _PLWE_POOL is not None and _PLWE_POOL_WORKERS == workers:
            return _PLWE_POOL
        if _PLWE_POOL is not None:
            try:
                _PLWE_POOL.terminate()
                _PLWE_POOL.join()
            except Exception:
                pass
            _PLWE_POOL = None
            _PLWE_POOL_WORKERS = 0
        try:
            ctx = multiprocessing.get_context("forkserver")
            _PLWE_POOL = ctx.Pool(processes=workers)
            _PLWE_POOL_WORKERS = workers
            return _PLWE_POOL
        except Exception:
            return None


def _worker_get_plwe_key(seed: bytes) -> "BlindClientPlweKey":
    key = _WORKER_PLWE_KEYS.get(seed)
    if key is None:
        if len(_WORKER_PLWE_KEYS) >= 16:
            _WORKER_PLWE_KEYS.clear()
        key = BlindClientPlweKey(seed)
        _WORKER_PLWE_KEYS[seed] = key
    return key


def _worker_encrypt_chunk(args: tuple[bytes, list[int], bool]) -> list[Any]:
    seed, vals, as_hex = args
    key = _worker_get_plwe_key(seed)
    if as_hex:
        return [key.encrypt_int(v).hex() for v in vals]
    return [key.encrypt_int(v) for v in vals]


def _worker_decrypt_chunk(args: tuple[bytes, list[bytes | str]]) -> list[int]:
    seed, frames = args
    key = _worker_get_plwe_key(seed)
    return [key.decrypt_int(fr) for fr in frames]


def _coerce_frame_bytes(frame: bytes | bytearray | memoryview | str, label: str = "frame") -> bytes:
    if isinstance(frame, str):
        raw = bytes.fromhex(frame.strip())
    elif isinstance(frame, (bytes, bytearray, memoryview)):
        raw = bytes(frame)
    else:
        raise TypeError(f"{label} must be bytes or hex str")
    return raw


def _expand_plwe_a(seed_a: bytes) -> list[int]:
    if len(seed_a) != 16:
        raise ValueError("seed_a must be exactly 16 bytes")
    pref = hashlib.sha256(b"PLWE0001-D0-A" + seed_a)
    q0 = LWE_Q0
    a = [0] * LWE_DIM
    from_bytes = int.from_bytes
    for ctr in range(LWE_DIM // 2):
        h = pref.copy()
        h.update(ctr.to_bytes(4, "little"))
        d = h.digest()
        v0 = from_bytes(d[:16], "little") & q0
        v1 = from_bytes(d[16:], "little") & q0
        a[2 * ctr] = 0 if v0 == q0 else v0
        a[2 * ctr + 1] = 0 if v1 == q0 else v1
    return a


def _unpack_plwe_components(frame: bytes | bytearray | memoryview | str) -> tuple[list[int], int]:
    raw = _coerce_frame_bytes(frame, "PLWE0001 frame")
    if len(raw) < 64 or raw[:8] != PLWE_MAGIC:
        raise ValueError("invalid PLWE0001 header magic")
    ver, prof, n_val, k_val, t_mod, _scale, _qid, seed_a, plen, stored_crc = struct.unpack(
        "<HBBIQQq16sII", raw[8:64]
    )
    if ver != 1 or prof != PLWE_PROFILE_D0 or n_val != 1 or k_val != 1:
        raise ValueError(f"unsupported PLWE0001 header params: ver={ver} prof={prof}")
    if t_mod != LWE_PLAIN_MOD:
        raise ValueError(f"unexpected LWE_PLAIN_MOD: {t_mod}")
    payload = raw[64:]
    if len(payload) != plen:
        raise ValueError(f"PLWE0001 payload length mismatch: expected {plen}, got {len(payload)}")
    if crc32c(raw[:60] + payload) != stored_crc:
        raise ValueError("PLWE0001 CRC-32C checksum mismatch")
    if plen == 16:
        a = _expand_plwe_a(seed_a)
        b = int.from_bytes(payload, "little") % LWE_Q0
        return a, b
    if plen == (LWE_DIM + 1) * 16:
        from_bytes = int.from_bytes
        a = [from_bytes(payload[i * 16 : (i + 1) * 16], "little") % LWE_Q0 for i in range(LWE_DIM)]
        b = from_bytes(payload[LWE_DIM * 16 : (LWE_DIM + 1) * 16], "little") % LWE_Q0
        return a, b
    raise ValueError(f"unsupported PLWE0001 payload length: {plen}")


def _pack_plwe_expanded(a: list[int], b: int) -> bytes:
    if len(a) != LWE_DIM:
        raise ValueError(f"expanded LWE vector must have length {LWE_DIM}")
    q0 = LWE_Q0
    buf = bytearray((LWE_DIM + 1) * 16)
    for i, ai in enumerate(a):
        buf[i * 16 : (i + 1) * 16] = (ai % q0).to_bytes(16, "little")
    buf[LWE_DIM * 16 : (LWE_DIM + 1) * 16] = (b % q0).to_bytes(16, "little")
    payload = bytes(buf)
    hdr60 = PLWE_MAGIC + struct.pack(
        "<HBBIQQq16sI",
        1,
        PLWE_PROFILE_D0,
        1,
        1,
        LWE_PLAIN_MOD,
        1,
        1,
        bytes(16),
        len(payload),
    )
    crc = crc32c(hdr60 + payload)
    return hdr60 + struct.pack("<I", crc) + payload


class BlindClientPlweKey:
    """
    Client-held Depth-0 additive homomorphic LWE key (PLWE0001, profile 0).

    The ternary secret vector s in {-1, 0, 1}^1024 never leaves the client.
    - Client encrypts signed integers into 80-byte randomized IND-CPA frames.
    - Server evaluates SUM and WEIGHTED_SUM strictly over ciphertexts with zero
      keys and returns a 16,464-byte expanded PLWE0001 ciphertext.
    - Client decrypts locally with exact integer recovery mod LWE_PLAIN_MOD.
    """

    def __init__(self, secret_seed: bytes) -> None:
        if not isinstance(secret_seed, (bytes, bytearray)) or len(secret_seed) != 32:
            raise ValueError("secret_seed must be exactly 32 bytes")
        self._seed = bytes(secret_seed)
        sk: list[int] = []
        for ctr in range(8):
            blk = hashlib.sha256(
                b"BLINDCORE-D0-S" + self._seed + ctr.to_bytes(4, "little")
            ).digest()
            for byte in blk:
                v = byte
                for _ in range(4):
                    sk.append((v & 1) - ((v >> 1) & 1))
                    v >>= 2
        self._sk: tuple[int, ...] = tuple(sk)
        # Precompute non-zero secret pairs to skip (0, 0) SHA-256 blocks identically
        self._active_pairs: tuple[tuple[bytes, int, int], ...] = tuple(
            (ctr.to_bytes(4, "little"), sk[2 * ctr], sk[2 * ctr + 1])
            for ctr in range(LWE_DIM // 2)
            if sk[2 * ctr] != 0 or sk[2 * ctr + 1] != 0
        )
        self._pos_indices: tuple[int, ...] = tuple(i for i, s in enumerate(sk) if s == 1)
        self._neg_indices: tuple[int, ...] = tuple(i for i, s in enumerate(sk) if s == -1)
        if _np is not None:
            self._np_pos_idx: Any = _np.array(self._pos_indices, dtype=_np.intp)
            self._np_neg_idx: Any = _np.array(self._neg_indices, dtype=_np.intp)
        else:
            self._np_pos_idx = None
            self._np_neg_idx = None

    @classmethod
    def generate(cls) -> "BlindClientPlweKey":
        return cls(secrets.token_bytes(32))

    @classmethod
    def from_seed(cls, seed: bytes) -> "BlindClientPlweKey":
        return cls(seed)

    @property
    def seed(self) -> bytes:
        return self._seed

    def encrypt_int(self, val: int) -> bytes:
        """Encrypt a signed integer into an 80-byte IND-CPA seeded PLWE0001 frame."""
        ival = int(val)
        half = LWE_PLAIN_MOD // 2
        if ival < -half or ival > half:
            raise ValueError(f"plaintext integer out of signed range [-{half}, {half}]")
        seed_a = os.urandom(16)
        eb = os.urandom(1)[0]
        err = (eb & 7).bit_count() - ((eb >> 3) & 7).bit_count()
        pref = hashlib.sha256(b"PLWE0001-D0-A" + seed_a)
        q0 = LWE_Q0
        from_bytes = int.from_bytes
        dot = 0
        for ctr_le, s0, s1 in self._active_pairs:
            h = pref.copy()
            h.update(ctr_le)
            d = h.digest()
            if s0:
                v0 = from_bytes(d[:16], "little") & q0
                if v0 != q0:
                    dot += v0 if s0 == 1 else -v0
            if s1:
                v1 = from_bytes(d[16:], "little") & q0
                if v1 != q0:
                    dot += v1 if s1 == 1 else -v1
        dot %= q0
        b = (dot + (ival % LWE_PLAIN_MOD) + err * LWE_PLAIN_MOD) % q0
        payload = b.to_bytes(16, "little")
        hdr60 = PLWE_MAGIC + struct.pack(
            "<HBBIQQq16sI",
            1,
            PLWE_PROFILE_D0,
            1,
            1,
            LWE_PLAIN_MOD,
            1,
            1,
            seed_a,
            16,
        )
        crc = crc32c(hdr60 + payload)
        return hdr60 + struct.pack("<I", crc) + payload

    def encrypt_int_hex(self, val: int) -> str:
        return self.encrypt_int(val).hex()

    def _resolve_batch_workers(self, n_items: int, workers: int | None, min_parallel: int) -> int:
        if workers is not None:
            w = int(workers)
            if w <= 1 or n_items < 2:
                return 1
            return min(w, n_items)
        if n_items < min_parallel:
            return 1
        cpus = os.cpu_count() or 1
        return max(1, min(8, cpus, n_items // 16))

    def encrypt_batch(self, vals: Sequence[int], workers: int | None = None) -> list[bytes]:
        """Encrypt a sequence of signed integers into fresh IND-CPA PLWE0001 frames."""
        items = [int(v) for v in vals]
        n = len(items)
        if n == 0:
            return []
        w = self._resolve_batch_workers(n, workers, min_parallel=96)
        if w > 1:
            pool = _get_plwe_pool(w)
            if pool is not None:
                chunk_sz = (n + w - 1) // w
                tasks = [
                    (self._seed, items[i : i + chunk_sz], False)
                    for i in range(0, n, chunk_sz)
                ]
                out: list[bytes] = []
                for part in pool.map(_worker_encrypt_chunk, tasks):
                    out.extend(part)
                return out
        return [self.encrypt_int(v) for v in items]

    def encrypt_batch_hex(self, vals: Sequence[int], workers: int | None = None) -> list[str]:
        """Encrypt a sequence of signed integers directly into hex PLWE0001 frames."""
        items = [int(v) for v in vals]
        n = len(items)
        if n == 0:
            return []
        w = self._resolve_batch_workers(n, workers, min_parallel=96)
        if w > 1:
            pool = _get_plwe_pool(w)
            if pool is not None:
                chunk_sz = (n + w - 1) // w
                tasks = [
                    (self._seed, items[i : i + chunk_sz], True)
                    for i in range(0, n, chunk_sz)
                ]
                out: list[str] = []
                for part in pool.map(_worker_encrypt_chunk, tasks):
                    out.extend(part)
                return out
        return [self.encrypt_int(v).hex() for v in items]

    def decrypt_batch(
        self,
        frames: Sequence[bytes | bytearray | memoryview | str],
        workers: int | None = None,
    ) -> list[int]:
        """Decrypt a sequence of PLWE0001 frames locally."""
        items = list(frames)
        n = len(items)
        if n == 0:
            return []
        min_par = 128 if _np is not None else 32
        w = self._resolve_batch_workers(n, workers, min_parallel=min_par)
        if w > 1:
            pool = _get_plwe_pool(w)
            if pool is not None:
                norm_items = [
                    bytes(fr) if isinstance(fr, (bytearray, memoryview)) else fr
                    for fr in items
                ]
                chunk_sz = (n + w - 1) // w
                tasks = [
                    (self._seed, norm_items[i : i + chunk_sz])
                    for i in range(0, n, chunk_sz)
                ]
                out: list[int] = []
                for part in pool.map(_worker_decrypt_chunk, tasks):
                    out.extend(part)
                return out
        return [self.decrypt_int(fr) for fr in items]

    def _decrypt_from_dot(self, dot: int, b: int) -> int:
        diff = (b - dot) % LWE_Q0
        if diff > LWE_Q0 // 2:
            rem = (LWE_Q0 - diff) % LWE_PLAIN_MOD
            raw = 0 if rem == 0 else LWE_PLAIN_MOD - rem
        else:
            raw = diff % LWE_PLAIN_MOD
        return raw - LWE_PLAIN_MOD if raw > LWE_PLAIN_MOD // 2 else raw

    def decrypt_int(self, frame: bytes | bytearray | memoryview | str) -> int:
        """Decrypt an 80-byte seeded or 16,464-byte expanded PLWE0001 frame locally."""
        if _np is not None and self._np_pos_idx is not None:
            raw = _coerce_frame_bytes(frame, "PLWE0001 frame")
            if len(raw) == PLWE_EXPANDED_BYTES and raw[:8] == PLWE_MAGIC:
                ver, prof, n_val, k_val, t_mod, _sc, _qid, _sa, plen, stored_crc = struct.unpack(
                    "<HBBIQQq16sII", raw[8:64]
                )
                if (
                    ver == 1
                    and prof == PLWE_PROFILE_D0
                    and n_val == 1
                    and k_val == 1
                    and t_mod == LWE_PLAIN_MOD
                    and plen == (LWE_DIM + 1) * 16
                ):
                    payload = raw[64:]
                    if crc32c(raw[:60] + payload) != stored_crc:
                        raise ValueError("PLWE0001 CRC-32C checksum mismatch")
                    limbs = _np.frombuffer(payload, dtype="<u4").reshape(LWE_DIM + 1, 4)
                    p = limbs[self._np_pos_idx].sum(axis=0, dtype=_np.uint64)
                    n = limbs[self._np_neg_idx].sum(axis=0, dtype=_np.uint64)
                    dot_pos = (
                        int(p[0])
                        + (int(p[1]) << 32)
                        + (int(p[2]) << 64)
                        + (int(p[3]) << 96)
                    )
                    dot_neg = (
                        int(n[0])
                        + (int(n[1]) << 32)
                        + (int(n[2]) << 64)
                        + (int(n[3]) << 96)
                    )
                    b_row = limbs[LWE_DIM]
                    b = (
                        int(b_row[0])
                        + (int(b_row[1]) << 32)
                        + (int(b_row[2]) << 64)
                        + (int(b_row[3]) << 96)
                    ) % LWE_Q0
                    return self._decrypt_from_dot((dot_pos - dot_neg) % LWE_Q0, b)
        a, b = _unpack_plwe_components(frame)
        dot = (sum(a[i] for i in self._pos_indices) - sum(a[i] for i in self._neg_indices)) % LWE_Q0
        return self._decrypt_from_dot(dot, b)

    @staticmethod
    def homomorphic_add(
        ct_a: bytes | bytearray | memoryview | str,
        ct_b: bytes | bytearray | memoryview | str,
    ) -> bytes:
        """Zero-key homomorphic ciphertext addition returning a 16,464-byte PLWE0001 frame."""
        a1, b1 = _unpack_plwe_components(ct_a)
        a2, b2 = _unpack_plwe_components(ct_b)
        q0 = LWE_Q0
        return _pack_plwe_expanded([(x + y) % q0 for x, y in zip(a1, a2)], (b1 + b2) % q0)

    @staticmethod
    def homomorphic_scale(
        ct: bytes | bytearray | memoryview | str,
        weight: int,
    ) -> bytes:
        """Zero-key homomorphic scalar multiplication returning a 16,464-byte PLWE0001 frame."""
        a1, b1 = _unpack_plwe_components(ct)
        q0 = LWE_Q0
        w = int(weight) % q0
        return _pack_plwe_expanded([(x * w) % q0 for x in a1], (b1 * w) % q0)

    @staticmethod
    def homomorphic_weighted_sum(
        frames: list[bytes | bytearray | memoryview | str],
        weights: list[int] | None = None,
    ) -> bytes:
        """Zero-key homomorphic weighted sum returning a 16,464-byte PLWE0001 frame."""
        q0 = LWE_Q0
        acc_a = [0] * LWE_DIM
        acc_b = 0
        if not frames:
            return _pack_plwe_expanded(acc_a, 0)
        if weights is not None and len(weights) != len(frames):
            raise ValueError("weights length must match frames length")
        for idx, fr in enumerate(frames):
            w = 1 if weights is None else int(weights[idx])
            if w == 0:
                continue
            a_i, b_i = _unpack_plwe_components(fr)
            w_mod = w % q0
            if w_mod == 1:
                for j in range(LWE_DIM):
                    acc_a[j] = (acc_a[j] + a_i[j]) % q0
                acc_b = (acc_b + b_i) % q0
            else:
                for j in range(LWE_DIM):
                    acc_a[j] = (acc_a[j] + a_i[j] * w_mod) % q0
                acc_b = (acc_b + b_i * w_mod) % q0
        return _pack_plwe_expanded(acc_a, acc_b)


# Compact pure-stdlib NIST SP 800-38D AES-256-GCM fallback (used only when
# `cryptography` is not installed so blindcore_sdk.py remains 0-dep).
_AES_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)
_AES_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40)


def _aes256_expand_key(key: bytes) -> list[bytes]:
    w = [list(key[i : i + 4]) for i in range(0, 32, 4)]
    for i in range(8, 60):
        t = list(w[i - 1])
        if i % 8 == 0:
            t = [_AES_SBOX[t[1]] ^ _AES_RCON[(i // 8) - 1], _AES_SBOX[t[2]], _AES_SBOX[t[3]], _AES_SBOX[t[0]]]
        elif i % 8 == 4:
            t = [_AES_SBOX[b] for b in t]
        w.append([w[i - 8][j] ^ t[j] for j in range(4)])
    return [bytes(sum(w[r * 4 : (r + 1) * 4], [])) for r in range(15)]


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1)


def _aes256_encrypt_block(rk: list[bytes], block: bytes) -> bytes:
    s = [block[i] ^ rk[0][i] for i in range(16)]
    for r in range(1, 15):
        s = [_AES_SBOX[b] for b in s]
        s = [
            s[0], s[5], s[10], s[15],
            s[4], s[9], s[14], s[3],
            s[8], s[13], s[2], s[7],
            s[12], s[1], s[6], s[11],
        ]
        if r != 14:
            ns = [0] * 16
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = s[c], s[c + 1], s[c + 2], s[c + 3]
                t = a0 ^ a1 ^ a2 ^ a3
                ns[c] = a0 ^ t ^ _xtime(a0 ^ a1)
                ns[c + 1] = a1 ^ t ^ _xtime(a1 ^ a2)
                ns[c + 2] = a2 ^ t ^ _xtime(a2 ^ a3)
                ns[c + 3] = a3 ^ t ^ _xtime(a3 ^ a0)
            s = ns
        k = rk[r]
        s = [s[i] ^ k[i] for i in range(16)]
    return bytes(s)


def _gf128_mul(x: int, y: int) -> int:
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ (0xE1 << 120)
        else:
            v >>= 1
    return z


def _ghash(h_int: int, aad: bytes, ct: bytes) -> bytes:
    y = 0
    for buf in (aad, ct):
        rem = len(buf) % 16
        padded = buf + (bytes(16 - rem) if rem else b"")
        for off in range(0, len(padded), 16):
            blk = int.from_bytes(padded[off : off + 16], "big")
            y = _gf128_mul(y ^ blk, h_int)
    lens = ((len(aad) * 8) << 64) | (len(ct) * 8)
    y = _gf128_mul(y ^ lens, h_int)
    return y.to_bytes(16, "big")


class _PureAes256Gcm:
    """Zero-dependency NIST SP 800-38D AES-256-GCM fallback."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("AES-256-GCM key must be 32 bytes")
        self._rk = _aes256_expand_key(key)
        self._h = int.from_bytes(_aes256_encrypt_block(self._rk, bytes(16)), "big")

    def _ctr_xor(self, nonce: bytes, data: bytes) -> bytes:
        out = bytearray(len(data))
        ctr = 2
        for off in range(0, len(data), 16):
            ks = _aes256_encrypt_block(self._rk, nonce + struct.pack(">I", ctr))
            chunk = data[off : off + 16]
            out[off : off + len(chunk)] = bytes(a ^ b for a, b in zip(chunk, ks))
            ctr = (ctr + 1) & 0xFFFFFFFF
        return bytes(out)

    def encrypt(self, nonce: bytes, data: bytes, aad: bytes) -> bytes:
        if len(nonce) != 12:
            raise ValueError("AES-GCM nonce must be 12 bytes")
        ct = self._ctr_xor(nonce, data)
        j0 = _aes256_encrypt_block(self._rk, nonce + b"\x00\x00\x00\x01")
        s_tag = _ghash(self._h, aad, ct)
        tag = bytes(a ^ b for a, b in zip(j0, s_tag))
        return ct + tag

    def decrypt(self, nonce: bytes, data: bytes, aad: bytes) -> bytes:
        if len(nonce) != 12 or len(data) < 16:
            raise ValueError("invalid AES-GCM ciphertext or nonce")
        ct, tag = data[:-16], data[-16:]
        j0 = _aes256_encrypt_block(self._rk, nonce + b"\x00\x00\x00\x01")
        expected = bytes(a ^ b for a, b in zip(j0, _ghash(self._h, aad, ct)))
        if not hmac.compare_digest(tag, expected):
            raise ValueError("AES-256-GCM authentication tag verification failed")
        return self._ctr_xor(nonce, ct)


class BlindClientEnvelopeKey:
    """
    Client-held SBLB0001 padded AEAD envelope and blind-token key.

    Server validates only the 24-byte SBLB0001 header, bucket size in
    {64, 128, 256, 512, 1024, 2048, 4096}, and 16-byte authentication tag.
    The AES-256-GCM DEK and blind-token HMAC key never leave the client.
    """

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            raise ValueError("envelope key must be exactly 32 bytes")
        self._key = bytes(key)
        self._tok_key = hmac.new(self._key, b"blindcore:sblb:tok:v1", hashlib.sha256).digest()
        self._path_key = hmac.new(self._key, b"blindcore:sblb:path:v1", hashlib.sha256).digest()
        self._aead: Any = (
            _CRYPTO_AESGCM(self._key) if _CRYPTO_AESGCM is not None else _PureAes256Gcm(self._key)
        )

    @classmethod
    def generate(cls) -> "BlindClientEnvelopeKey":
        return cls(secrets.token_bytes(32))

    @classmethod
    def from_key(cls, key: bytes) -> "BlindClientEnvelopeKey":
        return cls(key)

    @property
    def key(self) -> bytes:
        return self._key

    def seal(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Seal bytes into an SBLB0001 power-of-two bucketed AES-256-GCM frame."""
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext must be bytes")
        pt = bytes(plaintext)
        need = 4 + len(pt)
        bucket = 0
        for cand in SBLB_BUCKETS:
            if cand >= need:
                bucket = cand
                break
        if bucket == 0:
            raise ValueError(f"plaintext too large for SBLB0001 max bucket ({SBLB_BUCKETS[-1] - 4} B)")
        padded = struct.pack(">I", len(pt)) + pt + bytes(bucket - need)
        nonce = os.urandom(12)
        hdr24 = SBLB_MAGIC + struct.pack("<HH", 1, bucket) + nonce
        ct_tag = self._aead.encrypt(nonce, padded, hdr24 + aad)
        return hdr24 + ct_tag

    def seal_hex(self, plaintext: bytes, aad: bytes = b"") -> str:
        return self.seal(plaintext, aad=aad).hex()

    def open(self, frame: bytes | bytearray | memoryview | str, aad: bytes = b"") -> bytes:
        """Authenticate and unpad an SBLB0001 frame locally."""
        raw = _coerce_frame_bytes(frame, "SBLB0001 frame")
        if len(raw) < 40 or raw[:8] != SBLB_MAGIC:
            raise ValueError("invalid SBLB0001 header magic")
        ver, bucket = struct.unpack("<HH", raw[8:12])
        if ver != 1 or bucket not in SBLB_BUCKETS:
            raise ValueError(f"unsupported SBLB0001 version/bucket: ver={ver} bucket={bucket}")
        if len(raw) != 24 + bucket + 16:
            raise ValueError("SBLB0001 frame length mismatch")
        hdr24 = raw[:24]
        nonce = raw[12:24]
        ct_tag = raw[24:]
        try:
            padded = self._aead.decrypt(nonce, ct_tag, hdr24 + aad)
        except Exception as exc:
            raise ValueError("SBLB0001 AES-256-GCM decryption failed") from exc
        if len(padded) != bucket:
            raise ValueError("SBLB0001 decrypted bucket length mismatch")
        pt_len = struct.unpack(">I", padded[:4])[0]
        if pt_len > bucket - 4:
            raise ValueError("SBLB0001 invalid plaintext length prefix")
        if any(padded[4 + pt_len :]):
            raise ValueError("SBLB0001 non-zero padding bytes")
        return padded[4 : 4 + pt_len]

    def seal_json(self, obj: Any, aad: bytes = b"") -> bytes:
        raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return self.seal(raw, aad=aad)

    def seal_json_hex(self, obj: Any, aad: bytes = b"") -> str:
        return self.seal_json(obj, aad=aad).hex()

    def open_json(self, frame: bytes | bytearray | memoryview | str, aad: bytes = b"") -> Any:
        return json.loads(self.open(frame, aad=aad).decode("utf-8"))

    def blind_token_hex(self, namespace: str, value: str) -> str:
        """Derive a 32-byte (64-hex) client-keyed HMAC-SHA256 blind token."""
        return hmac.new(
            self._tok_key,
            f"{namespace}:{value}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def derive_path_token_hex(self, path: str) -> str:
        """Derive a 32-byte (64-hex) client-keyed BlindJSONB numeric path token."""
        return hmac.new(
            self._path_key,
            f"path:{path}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()


def generate_zero_sum_masks(
    secret_key: bytes,
    cohort_id: str,
    count: int,
    bound: int = 500_000,
    floor: int = 100_000,
) -> list[int]:
    """
    Generate secret-keyed HMAC-SHA256 zero-sum blinding masks for a cohort.

    Requires a >= 32-byte client/consortium secret key so masks cannot be
    reconstructed from the public or semi-public cohort identifier alone.
    """
    if not isinstance(secret_key, (bytes, bytearray)) or len(secret_key) < 32:
        raise ValueError("secret_key must be at least 32 bytes")
    if count < 0:
        raise ValueError("count must be non-negative")
    if count <= 1:
        return [0] * count
    if bound <= 0 or floor < 0:
        raise ValueError("bound must be > 0 and floor >= 0")
    masks: list[int] = []
    running = 0
    key_bytes = bytes(secret_key)
    for idx in range(count - 1):
        digest = hmac.new(
            key_bytes,
            f"blindcore:mask:v1|{cohort_id}|{idx}".encode("utf-8"),
            hashlib.sha256,
        ).digest()
        val = int.from_bytes(digest[:4], "big") % bound + floor
        if digest[4] & 1:
            val = -val
        masks.append(val)
        running += val
    masks.append(-running)
    return masks


def verify_blind_receipt(
    resp: dict[str, Any],
    kind: str,
    table: str,
    count: int,
    payload: bytes,
) -> bool:
    """Verify a live server NSAU0001 cryptographic query/ingest receipt."""
    if not isinstance(resp, dict):
        return False
    if resp.get("receipt_magic") != "NSAU0001":
        return False
    got = resp.get("receipt_hex")
    if not isinstance(got, str) or len(got) != 64:
        return False
    expected = hashlib.sha256(
        b"NSAU0001:BLIND:"
        + kind.encode("utf-8")
        + b":"
        + table.encode("utf-8")
        + struct.pack("<Q", int(count))
        + payload
    ).hexdigest()
    return hmac.compare_digest(got.lower(), expected)
