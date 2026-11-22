#!/usr/bin/env python3
"""
BlindCore Zero-Dependency JSON-RPC 2.0 MCP Server (SPDX-License-Identifier: Apache-2.0).

Exposes BlindCore Tri-Rail confidential compute tools over Model Context
Protocol (MCP) stdio transport using Python 3 standard library only:
  - blindcore_pricing: Inspect live tri-rail pricing & x402 v2 discovery.
  - blindcore_query: Execute encrypted CONTAINS/LATEST/SUM/WEIGHTED_SUM/RANGE_GATE/BLIND_PIPELINE queries.
  - blindcore_sklearn_mnb: Execute single-pass encrypted MultinomialNB training and cohort scoring.
"""

from __future__ import annotations

import base64
import json
import os
import sys
from typing import Any
import urllib.error
import urllib.parse
import urllib.request


MCP_PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "blindcore-mcp", "version": "0.1.0"}
MAX_RESPONSE_BYTES = 2_097_152
MAX_HEADER_VALUE_BYTES = 65_536

ALLOWED_PAYMENT_HEADERS = frozenset((
    "PAYMENT-SIGNATURE",
    "X-PAYMENT",
    "Authorization",
    "X-Stacks-Payment-Tx",
    "X-BlindCore-Session",
))
_PAYMENT_HEADER_CANONICAL = {h.lower(): h for h in ALLOWED_PAYMENT_HEADERS}

ALLOWED_API_PREFIXES = (
    "/api/v1/",
    "/api/auction/",
    "/.well-known/",
    "/health",
    "/llms.txt",
)

ALLOWED_QUERY_ENDPOINTS = frozenset((
    "/api/v1/blind/jsonb/query",
    "/api/v1/blind/query",
    "/api/v1/blind/jsonb/ingest",
    "/api/v1/blind/ingest",
    "/api/auction/clear",
))


def _validate_base_url(url: str) -> str:
    if not isinstance(url, str):
        raise ValueError("base_url must be a string")
    cleaned = url.strip().rstrip("/")
    if not cleaned:
        raise ValueError("base_url must not be empty")
    if any(ch in cleaned for ch in ("\r", "\n", "\x00", " ", "\t")):
        raise ValueError("base_url contains illegal whitespace or control characters")
    parsed = urllib.parse.urlsplit(cleaned)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("base_url must use http or https scheme")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("base_url must specify a valid host without embedded credentials")
    if parsed.fragment or parsed.query:
        raise ValueError("base_url must not contain query or fragment components")
    return cleaned


def _validate_api_path(path: str) -> str:
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        raise ValueError(f"invalid API path: {path!r}")
    if any(ch in path for ch in ("\r", "\n", "\x00", "\\", "@", "?", "#")):
        raise ValueError(f"illegal character in API path: {path!r}")
    decoded = urllib.parse.unquote(path)
    if any(ch in decoded for ch in ("\r", "\n", "\x00", "\\", "@", "?", "#")):
        raise ValueError(f"illegal encoded character in API path: {path!r}")
    if "//" in decoded or ".." in decoded.split("/"):
        raise ValueError(f"path traversal rejected: {path!r}")
    if not any(decoded.startswith(prefix) for prefix in ALLOWED_API_PREFIXES):
        raise ValueError(f"disallowed API path prefix: {decoded!r}")
    return decoded


def _sanitize_payment_headers(overrides: dict[str, Any]) -> dict[str, str]:
    if not isinstance(overrides, dict):
        raise ValueError("payment_headers must be an object")
    clean: dict[str, str] = {}
    for raw_k, raw_v in overrides.items():
        if not isinstance(raw_k, str) or not isinstance(raw_v, str):
            raise ValueError("payment header keys and values must be strings")
        k_stripped = raw_k.strip()
        v_stripped = raw_v.strip()
        if any(ch in k_stripped for ch in ("\r", "\n", "\x00")) or any(
            ch in v_stripped for ch in ("\r", "\n", "\x00")
        ):
            raise ValueError("CRLF or null byte rejected in payment header")
        canonical = _PAYMENT_HEADER_CANONICAL.get(k_stripped.lower())
        if canonical is None:
            raise ValueError(f"disallowed payment header: {k_stripped}")
        if not v_stripped:
            continue
        if len(v_stripped) > MAX_HEADER_VALUE_BYTES:
            raise ValueError(f"payment header {canonical} exceeds size cap")
        clean[canonical] = v_stripped
    return clean


def _decode_b64_header(val: str | None) -> Any:
    if not val:
        return None
    raw = val.strip()
    if len(raw) > MAX_HEADER_VALUE_BYTES:
        return None
    pad = (-len(raw)) % 4
    if pad == 3:
        return val
    if pad:
        raw += "=" * pad
    try:
        return json.loads(base64.b64decode(raw, validate=True).decode("utf-8"))
    except Exception:
        return val


class BlindCoreHttpClient:
    """Stdlib HTTP client speaking BlindCore tri-rail headers."""

    def __init__(
        self,
        base_url: str | None = None,
        session_token: str | None = None,
        x402_signature: str | None = None,
        l402_token: str | None = None,
        stacks_txid: str | None = None,
        timeout_secs: float = 20.0,
    ) -> None:
        raw_base = base_url if base_url is not None else os.environ.get("BLINDCORE_GATE_URL", "http://127.0.0.1:3002")
        self.base_url = _validate_base_url(raw_base)
        self.session_token = session_token or os.environ.get("BLINDCORE_SESSION_TOKEN", "")
        self.x402_signature = x402_signature or os.environ.get("BLINDCORE_X402_SIGNATURE", "")
        self.l402_token = l402_token or os.environ.get("BLINDCORE_L402_TOKEN", "")
        self.stacks_txid = stacks_txid or os.environ.get("BLINDCORE_STACKS_TXID", "")
        self.timeout_secs = timeout_secs

    def _payment_headers(
        self,
        overrides: dict[str, str] | None = None,
        suppress_default_payment: bool = False,
    ) -> dict[str, str]:
        headers: dict[str, str] = {"Accept": "application/json"}
        if overrides is not None:
            headers.update(_sanitize_payment_headers(overrides))
            return headers
        if not suppress_default_payment:
            if self.session_token:
                headers.update(_sanitize_payment_headers({"X-BlindCore-Session": self.session_token}))
            elif self.x402_signature:
                headers.update(_sanitize_payment_headers({"PAYMENT-SIGNATURE": self.x402_signature}))
            elif self.l402_token:
                headers.update(_sanitize_payment_headers({"Authorization": f"L402 {self.l402_token}"}))
            elif self.stacks_txid:
                headers.update(_sanitize_payment_headers({"X-Stacks-Payment-Tx": self.stacks_txid}))
        return headers

    def get_json(self, path: str) -> dict[str, Any]:
        clean_path = _validate_api_path(path)
        req = urllib.request.Request(f"{self.base_url}{clean_path}", method="GET", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout_secs) as resp:
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise ValueError("gateway response exceeds size limit")
            parsed = json.loads(raw.decode("utf-8"))
            if not isinstance(parsed, dict):
                raise ValueError("gateway response must be a JSON object")
            return parsed

    def post_paid(
        self,
        path: str,
        payload: dict[str, Any],
        payment_headers: dict[str, str] | None = None,
        suppress_default_payment: bool = False,
    ) -> dict[str, Any]:
        clean_path = _validate_api_path(path)
        headers = self._payment_headers(payment_headers, suppress_default_payment=suppress_default_payment)
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        req = urllib.request.Request(f"{self.base_url}{clean_path}", data=data, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_secs) as resp:
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise ValueError("gateway response exceeds size limit")
                body = json.loads(raw.decode("utf-8"))
                return {
                    "http_status": int(resp.status),
                    "body": body,
                    "payment_response": _decode_b64_header(resp.headers.get("PAYMENT-RESPONSE")),
                    "rail": resp.headers.get("X-BlindCore-Rail"),
                    "payment_hash": resp.headers.get("X-BlindCore-Payment-Hash"),
                }
        except urllib.error.HTTPError as exc:
            raw_err = exc.read(MAX_RESPONSE_BYTES).decode("utf-8", errors="replace")
            try:
                err_body = json.loads(raw_err)
            except Exception:
                err_body = {"raw": raw_err}
            return {
                "http_status": int(exc.code),
                "body": err_body,
                "payment_required": _decode_b64_header(exc.headers.get("PAYMENT-REQUIRED")),
                "www_authenticate": exc.headers.get("WWW-Authenticate"),
                "stacks_payment_required": _decode_b64_header(exc.headers.get("X-Stacks-Payment-Required")),
            }


TOOLS_SPEC = [
    {
        "name": "blindcore_pricing",
        "description": "Retrieve BlindCore Tri-Rail pricing tiers (Base x402 USDC, Lightning L402 sats, Stacks sBTC) and discovery endpoints.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "include_x402_manifest": {
                    "type": "boolean",
                    "description": "When true, include /.well-known/x402.json metadata alongside /api/v1/pricing.",
                    "default": False,
                }
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "blindcore_query",
        "description": "Execute a zero-plaintext encrypted BlindCore query (CONTAINS, LATEST, SUM, WEIGHTED_SUM, RANGE_GATE, BLIND_PIPELINE) over tri-rail HTTP 402.",
        "inputSchema": {
            "type": "object",
            "required": ["table", "op"],
            "properties": {
                "endpoint": {
                    "type": "string",
                    "default": "/api/v1/blind/jsonb/query",
                    "description": "Target BlindCore endpoint path.",
                },
                "table": {"type": "string", "description": "Encrypted collection or table name."},
                "op": {
                    "type": "string",
                    "enum": ["CONTAINS", "LATEST", "SUM", "WEIGHTED_SUM", "RANGE_GATE", "BLIND_PIPELINE"],
                },
                "params": {
                    "type": "object",
                    "description": "Additional operation-specific encrypted tokens, filters, weights, or pipeline stages.",
                },
                "payment_headers": {
                    "type": "object",
                    "description": "Optional per-call payment headers (PAYMENT-SIGNATURE, Authorization, X-Stacks-Payment-Tx, or X-BlindCore-Session).",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "blindcore_sklearn_mnb",
        "description": "Run single-pass encrypted MultinomialNB training and cohort scoring (op=SKLEARN_MNB) over encrypted JSONB documents.",
        "inputSchema": {
            "type": "object",
            "required": ["table", "train_classes", "vocab_paths"],
            "properties": {
                "table": {"type": "string", "description": "Encrypted collection name."},
                "train_classes": {"type": "array", "items": {"type": "object"}},
                "vocab_paths": {"type": "array", "items": {"type": "string"}},
                "score_cohorts": {"type": "array", "items": {"type": "object"}, "default": []},
                "alpha": {"type": "number", "default": 1.0},
                "weight_scale": {"type": "integer", "default": 10000},
                "threshold_decrypt": {"type": "object"},
                "payment_headers": {"type": "object"},
            },
            "additionalProperties": False,
        },
    },
]


def dispatch_tool(name: str, arguments: dict[str, Any], client: BlindCoreHttpClient) -> dict[str, Any]:
    if not isinstance(arguments, dict):
        raise ValueError("tool arguments must be a JSON object")

    if name == "blindcore_pricing":
        pricing = client.get_json("/api/v1/pricing")
        if arguments.get("include_x402_manifest"):
            pricing["x402_manifest"] = client.get_json("/.well-known/x402.json")
        return pricing

    if name == "blindcore_query":
        endpoint = str(arguments.get("endpoint") or "/api/v1/blind/jsonb/query")
        if endpoint not in ALLOWED_QUERY_ENDPOINTS:
            raise ValueError(f"disallowed query endpoint: {endpoint}")
        if "table" not in arguments or "op" not in arguments:
            raise ValueError("blindcore_query requires table and op")
        body: dict[str, Any] = {}
        extra = arguments.get("params")
        if extra is not None:
            if not isinstance(extra, dict):
                raise ValueError("params must be a JSON object")
            body.update(extra)
        # Set table and op AFTER extra so params cannot overwrite them
        body["table"] = str(arguments["table"])
        body["op"] = str(arguments["op"])
        pay_hdrs = arguments.get("payment_headers")
        if pay_hdrs is not None and not isinstance(pay_hdrs, dict):
            raise ValueError("payment_headers must be a JSON object")
        return client.post_paid(endpoint, body, pay_hdrs)

    if name == "blindcore_sklearn_mnb":
        body = {
            "table": str(arguments["table"]),
            "op": "SKLEARN_MNB",
            "train_classes": arguments["train_classes"],
            "vocab_paths": arguments["vocab_paths"],
            "score_cohorts": arguments.get("score_cohorts", []),
            "alpha": float(arguments.get("alpha", 1.0)),
            "weight_scale": int(arguments.get("weight_scale", 10000)),
        }
        if isinstance(arguments.get("threshold_decrypt"), dict):
            body["threshold_decrypt"] = arguments["threshold_decrypt"]
        pay_hdrs = arguments.get("payment_headers")
        if pay_hdrs is not None and not isinstance(pay_hdrs, dict):
            raise ValueError("payment_headers must be a JSON object")
        return client.post_paid(
            "/api/v1/blind/jsonb/query",
            body,
            pay_hdrs,
        )

    raise ValueError(f"unknown tool: {name}")


def handle_rpc_request(req: Any, client: BlindCoreHttpClient) -> dict[str, Any] | None:
    if not isinstance(req, dict):
        return {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32600, "message": "Invalid Request: expected JSON object"},
        }
    req_id = req.get("id")
    method = str(req.get("method", ""))
    raw_params = req.get("params")
    if raw_params is None:
        params: dict[str, Any] = {}
    elif isinstance(raw_params, dict):
        params = raw_params
    else:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32602, "message": "Invalid params: expected JSON object"},
        }

    if method == "notifications/initialized":
        return None

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "serverInfo": SERVER_INFO,
                "capabilities": {"tools": {}},
            },
        }

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS_SPEC}}

    if method == "tools/call":
        tool_name = str(params.get("name", ""))
        raw_args = params.get("arguments")
        if raw_args is None:
            arguments: dict[str, Any] = {}
        elif isinstance(raw_args, dict):
            arguments = raw_args
        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": "Invalid arguments: expected JSON object"},
            }
        try:
            result_obj = dispatch_tool(tool_name, arguments, client)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(result_obj, sort_keys=True)}],
                    "structuredContent": result_obj,
                    "isError": False,
                },
            }
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps({"error": str(exc)})}],
                    "isError": True,
                },
            }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def serve_stdio(client: BlindCoreHttpClient | None = None) -> None:
    cli = client or BlindCoreHttpClient()
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as exc:
            err = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}}
            sys.stdout.write(json.dumps(err) + "\n")
            sys.stdout.flush()
            continue
        resp = handle_rpc_request(req, cli)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    serve_stdio()
