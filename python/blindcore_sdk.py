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

import base64
import hashlib
import http.client
import json
import os
import socket
import ssl
import struct
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Iterator, List, Optional, Union

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


class ApiError(Exception):
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
    x_pay_req = lower.get("x-payment-required", "")
    protocols: List[str] = []
    if x_pay_req or (isinstance(body, dict) and body.get("x402Version")) or "x402" in www_auth.lower():
        protocols.append("x402")
    if "l402" in www_auth.lower() or (isinstance(body, dict) and (body.get("macaroon") or body.get("invoice"))):
        protocols.append("L402")
    if "sbtc" in www_auth.lower() or (isinstance(body, dict) and (body.get("sbtcAddress") or body.get("sbtc"))):
        protocols.append("sBTC")
    return {
        "status": 402,
        "protocols": protocols,
        "www_authenticate": www_auth,
        "x_payment_required": x_pay_req,
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
    ) -> tuple[int, dict[str, str], bytes]:
        if _has_ctl(path) or not path.startswith("/"):
            raise ValueError("path must begin with '/' and contain no control characters")
        conn = self._open_conn()
        try:
            conn.request(method, path, body=body, headers=self._headers(content_type, auth=auth))
            resp = conn.getresponse()
            hdrs = {k.lower(): v for k, v in resp.getheaders()}
            data = self._read_bounded_body(resp)
            return resp.status, hdrs, data
        finally:
            conn.close()

    def _post_bytes(self, path: str, body: bytes, content_type: str) -> bytes:
        status, _, data = self.request_raw("POST", path, body=body, content_type=content_type, auth=True)
        if status < 200 or status >= 300:
            raise RuntimeError(f"HTTP {status}: {data.decode('utf-8', 'replace').strip()}")
        return data

    def get_json(self, path: str, auth: bool = True) -> Any:
        status, _, data = self.request_raw("GET", path, body=None, content_type=None, auth=auth)
        if status < 200 or status >= 300:
            raise RuntimeError(f"HTTP {status}: {data.decode('utf-8', 'replace').strip()}")
        return json.loads(data.decode("utf-8"))

    def post_json(self, path: str, payload: dict[str, Any]) -> Any:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        return json.loads(self._post_bytes(path, encoded, "application/json").decode("utf-8"))

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
            if not isinstance(where, dict) or "column" not in where or "eq" not in where:
                raise ValueError("where must be a {'column': ..., 'eq': ...} dict")
            wcol = str(where["column"]).strip()
            if not wcol or _has_ctl(wcol):
                raise ValueError("where['column'] must be non-empty without control characters")
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
            self._post_bytes("/api/v1/query?format=json", q.encode("utf-8"), "text/plain; charset=utf-8").decode("utf-8")
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
        app_origin: str = "https://sign.blindcore.io",
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
        app_origin: str = "https://sign.blindcore.io",
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
