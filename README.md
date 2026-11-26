# BlindCore Developer SDK & Evaluation Kit

Official zero-dependency Python 3 and JavaScript/TypeScript (ESM) client SDK, Model Context Protocol (`MCP`) server, Coinbase AgentKit action provider, Tri-Rail `HTTP 402` payment gateway, L2 state-root anchor contracts, interactive evaluation notebooks, and end-to-end confidential compute applications for **BlindCore** by [Blind Labs](https://blindlabs.ai).

| Property | Specification |
| :--- | :--- |
| **Website** | https://blindlabs.ai |
| **Repository** | https://github.com/blindlabs-ai/blindcore-sdk |
| **Runtime Dependencies** | `0` external packages (Python 3 stdlib + standard WebCrypto & Fetch API) |
| **Client Cryptography** | `AES-256-GCM` + power-of-2 `PAD2`, `ECDSA P-256`, `ECDH P-256` + `HKDF-SHA-256`, `SHA-256` |
| **HTTP 402 Payment Rails** | Base L2 `USDC` (`x402 v2`), Bitcoin Lightning (`L402`), Stacks `sBTC`, Prepaid Sessions |
| **License** | Apache License, Version 2.0 ([LICENSE](LICENSE) & [NOTICE](NOTICE)) |

---

## Why BlindCore SDK?

- **Zero Supply-Chain Surface:** Both `python/blindcore_sdk.py` and `js/blindcore-web.js` run on standard-library primitives (`urllib`, `http.client`, `socket`, `ssl`, `hashlib`, `crypto.subtle`, `fetch`) with `0` third-party `pip` or `npm` runtime dependencies.
- **End-to-End Client Envelope Security:** Built-in `AES-256-GCM` encryption with `PAD2` power-of-2 length-hiding padding, `ECDSA P-256` detached document and post signatures, and `ECDH P-256` shared-key derivation for encrypted direct messages and group key rotation.
- **Full BlindCore Surface in One Kit:** Unified `BlindCoreClient` (SQL, Blind Homomorphic OLAP, BlindJSONB Encrypted NoSQL, encrypted `SKLEARN_MNB` scoring, NDJSON streaming, RFC 6455 live WebSockets), `BlindSignClient`, `BlindFeedClient`, and `BlindMailClient`.
- **Native AI Agent & Tri-Rail `HTTP 402` Monetization:** Ships a zero-dependency JSON-RPC 2.0 `MCP` stdio server (`mcp/mcp_server.py`), a Coinbase AgentKit provider (`mcp/agentkit_provider.py`), a reference Tri-Rail `HTTP 402` gateway (`gate/blindcore_trirail_gate.py`), and a zero-dependency Cloudflare Worker `x402 v2` edge proxy (`cloudflare-worker-x402/`).
- **Verifiable State-Root Anchoring & Reproducible Benchmarks:** Includes Base L2 Solidity (`BlindCoreRootAnchor.sol`) and Stacks Clarity (`blindcore-root-anchor.clar`) state-root anchors, `4` standalone Mode 2 confidential compute sample apps (`apps/`), a full zero-key encrypted `scikit-learn` estimator suite (`sklearn_blind/`, `23` estimators across `8` families with `11.99x` live radix-packed `BlindMultinomialNB` E2E speedup), and `11` reproducible Jupyter notebooks (`notebooks/`), including the [4-Pillar Encrypted Storage, Query, ML & Client-Side Zero-Knowledge Benchmark](notebooks/10_encrypted_storage_compression_benchmark.ipynb) and the [Encrypted `scikit-learn` Suite Benchmark](notebooks/11_encrypted_sklearn_suite_benchmark.ipynb).

---

## Cryptographic Operating Modes (Mode 1 vs. Mode 2)

BlindCore supports two explicit, auditable key-custody modes so security reviewers can match key boundaries to their threat model:

| Mode | Who Holds Secret Keys | Wire Payloads | Use Cases |
| :--- | :--- | :--- | :--- |
| **Mode 1: Server-Managed Enclave / At-Rest AEAD** | Server / TEE / HSM / `2-of-3` TKMS enclave | TLS-protected SQL/JSON or server-assisted `"seal_doc"` + `"threshold_decrypt"` | Compressed `AES-256-GCM` on-disk slabs (`7.999+ bits/B`), encrypted SQL (`SUM`, `WHERE`), in-engine `ML_LINEAR_SCORE`, and threshold-enclave `SKLEARN_MNB` (Notebook 10 Pillars 1-3) |
| **Mode 2: Pure Client-Side Zero-Knowledge Compute** | **Client holds `100%` of keys** (`BlindClientPlweKey` + `BlindClientEnvelopeKey`); **server holds `0` keys** | Strictly randomized IND-CPA `80 B` `PLWE0001` ciphertexts + `SBLB0001` (`PAD2` + `AES-256-GCM`) envelopes; **zero** `"seal_*"` / `"threshold_decrypt"` | Zero-trust homomorphic `SUM` and `WEIGHTED_SUM` (linear / log-odds scoring) returning `16,464 B` expanded `PLWE0001` ciphertexts + `NSAU0001` receipts with `"decrypted_aggregate"` absent, decrypted locally on client with `0` integer error (Notebook 10 Pillar 4, `apps/app01..app04`, `tests/test_live_zero_knowledge_audit.py`) |

---

## Safe-Compute Acceleration & Formal Verification Stack

BlindCore pairs zero-dependency client cryptography with Blind Labs' open-source native compilation and static verification toolchain so encrypted workloads run fast without expanding the trusted computing base:

| Component | Repository / Entrypoint | Architecture & Verified Evidence |
| :--- | :--- | :--- |
| **`zero-cc`** | [blindlabs-ai/zero-cc](https://github.com/blindlabs-ai/zero-cc) | `4,979`-LOC zero-LLVM register-pinned native compiler emitting `ELF64` (`AVX2` + `AArch64`) and `WASM32+SIMD128` directly with `0` stack spills (`48x-95x` safe compute acceleration). |
| **`zero-check`** | [blindlabs-ai/zero-check](https://github.com/blindlabs-ai/zero-check) | `4,063`-LOC `#![forbid(unsafe_code)]` Rust relational abstract interpreter (`DBM` + `Interval` + `i128` CRT + Shadow-Epoch memory), scanning `2.66M` LOC in `4.89s`. |
| **`zero_check_py`** | `PYTHONPATH=python python3 -m blindcore.zero_check_py` | Zero-dependency pure-Python `ast` interval & taint verifier (`0` Rust<>Python FFI) shipping directly inside this SDK (`python/blindcore/zero_check_py.py`). |

- **Continuous Defensive Vulnerability Discovery:** `zero-check` powers Blind Labs' internal continuous taint and domain-invariant verification engine across critical open-source infrastructure, surfacing real arithmetic, URL/parser, and boundary defects responsibly reported upstream (`oven-sh/bun#49579`, `lightningdevkit/rust-lightning#4767`, `payjoin/rust-payjoin#2082`, `rust-bitcoin/rust-bitcoin#7266`, and coordinated private advisory `GHSA-3946-9jcq-jwqq`).
- **Pure-Python SDK & Domain Verification (`zero_check_py`):** Runs with zero native extensions or FFI to enforce fixed-width wire-pack bounds (`PY-WIDTH-01`), Bitcoin/PLWE numeric and consensus domain limits (`PY-MSAT-02`, `PY-PLWE-03`, `PY-FLOAT-04`), URI/host, weak-crypto, constant-time MAC, and CSRF guards (`PY-URI-05`..`PY-CSRF-08`), and Merkle/Hensel structural invariants (`PY-MERKLE-09`).
- **Dogfooded to Zero Findings:** Running `zero_check_py` against this repository immediately caught and sealed `5` genuine `PY-WIDTH-01` pack-width bounds guards in `python/blindcore_sdk.py`, bringing the entire SDK (`python/` + `sklearn_blind/`) to `0` findings under `--domain all`.

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=python python3 -m blindcore.zero_check_py --domain all python sklearn_blind
```

---

## Quickstart

### 1. Browser, Edge Workers & Node 22+ (`js/blindcore-web.js`)

Copy `js/blindcore-web.js` (and `js/blindcore-web.d.ts` for TypeScript IDE types) directly into your application:

```js
import {
  BlindCrypto,
  BlindCoreClient,
  BlindSignClient,
  PaymentRequiredError
} from "./js/blindcore-web.js";

const core = new BlindCoreClient({
  baseUrl: "https://api.blindlabs.ai",
  onPaymentRequired: async (challenge) => {
    // Negotiate x402 v2 (Base USDC) or Stacks sBTC and return retry headers:
    // Base USDC (x402 v2): return { "PAYMENT-SIGNATURE": signedPaymentHeader };
    // Stacks sBTC:         return { "X-Stacks-Payment-Tx": stacksTxId };
    return null;
  }
});

// Live discovery endpoints: GET /health and GET /api/v1/pricing
const health = await core.health();
const pricing = await core.pricing();

// Metered encrypted BlindJSONB query: POST /api/v1/blind/jsonb/query
try {
  const res = await core.queryBlindJsonb({
    table: "private_records",
    op: "CONTAINS",
    path: "/tags",
    value: "priority"
  });
  console.log("BlindJSONB result:", res);
} catch (err) {
  if (err instanceof PaymentRequiredError) {
    console.log("Protocols:", err.challenge.protocols);
    console.log("x402 header:", Boolean(err.challenge.paymentRequired));
    console.log("Stacks header:", Boolean(err.challenge.stacksPaymentRequired));
  }
}

const sign = new BlindSignClient(core);
const signer = await BlindCrypto.generateSigningKeyPair();

const { envelopeId, inviteLink } = await sign.createEnvelope({
  fileBytes: "Mutual NDA v1.0",
  fileName: "nda.txt",
  title: "Mutual NDA",
  signers: ["partner@example.com"],
  signingPrivateKey: signer.privateKey
});

console.log("Envelope:", envelopeId, "Zero-knowledge invite:", inviteLink);
```

See [examples/custom-frontend.html](examples/custom-frontend.html) for a single-file browser starter.

### 2. Python 3 (`python/blindcore_sdk.py`)

```python
from python.blindcore_sdk import (
    BlindCoreClient,
    PaymentRequiredError,
    pad2,
    sha256_hex,
)

core = BlindCoreClient(
    base_url="https://api.blindlabs.ai",
    # Optional free-tier developer key (bl_live_*) for /api/v1/query & /api/v1/pricing:
    # token="bl_live_...",
    # Optional HTTP 402 payment hook returning {"PAYMENT-SIGNATURE": ...} or {"X-Stacks-Payment-Tx": ...}:
    # on_payment_required=my_payment_hook,
)

# Live discovery routes: GET /health and GET /api/v1/pricing
health = core.get_json("/health", auth=False)
pricing = core.get_json("/api/v1/pricing", auth=False)

# SQL (POST /api/v1/query?format=json) & BlindJSONB (POST /api/v1/blind/jsonb/query)
# Paid routes raise PaymentRequiredError when no payment header or hook is provided:
try:
    res = core.query_blind_jsonb(
        table="private_records",
        op="CONTAINS",
        path="/tags",
        value="priority",
    )
except PaymentRequiredError as exc:
    # Parses PAYMENT-REQUIRED (x402 v2), X-Stacks-Payment-Required (sBTC), and WWW-Authenticate (L402)
    print("402 protocols:", exc.challenge["protocols"])
    print("x402 header present:", bool(exc.challenge["payment_required"]))
    print("sBTC header present:", bool(exc.challenge["stacks_payment_required"]))

# Blind Homomorphic OLAP (POST /api/v1/blind/query) & read-only SQL (POST /api/v1/query)
# olap = core.query_blind(table="private_ledger", op="SUM", column="amount")
# rows = core.query_json("SELECT 1")

# Power-of-2 length-hiding PAD2 framing
padded = pad2(b"confidential payload", min_block=256)
digest = sha256_hex(padded)
```

### 3. AI Agents (`MCP` Stdio Server & Tri-Rail `HTTP 402` Gateway)

```bash
# Launch the zero-dependency JSON-RPC 2.0 MCP server over stdio
BLINDCORE_URL="https://api.blindlabs.ai" python3 mcp/mcp_server.py

# Inspect CLI options for the Tri-Rail HTTP 402 payment gateway & live evaluator
python3 gate/blindcore_trirail_gate.py --help
python3 eval_blindcore.py --help
```

---

## Repository Layout

```text
python/blindcore_sdk.py           # Zero-dep Python 3 SDK (SQL, Blind OLAP/JSONB, WS, Sign, Feed, Mail)
python/blindcore/zero_check_py.py # Zero-dep Python AST linter (width, msat, PLWE0001, URI, MAC, CSRF, Merkle)
sklearn_blind/                    # Encrypted scikit-learn suite (23 estimators across 8 families, radix-B packing)
js/blindcore-web.js               # Zero-dep ES2020 WebCrypto + Fetch SDK (Browser, Workers, Node 22+)
js/blindcore-web.d.ts             # TypeScript type definitions for blindcore-web.js
mcp/mcp_server.py                 # Zero-dep JSON-RPC 2.0 Model Context Protocol (MCP) stdio server
mcp/agentkit_provider.py          # Coinbase AgentKit BlindCoreActionProvider (Tri-Rail HTTP 402)
gate/blindcore_trirail_gate.py    # Reference Tri-Rail HTTP 402 payment gateway (x402 v2, L402, sBTC)
gate/test_trirail_gate.py         # Unit & integration test suite for Tri-Rail HTTP 402 verification
gate/test_trirail_redteam_fuzz.py # Deterministic 12,221-probe red-team & replay fuzz suite
apps/app01..app04_*.py            # Confidential compute sample apps (Brain, Darkpool, Fraud, Nostr)
examples/01..03_*.py              # Base x402, Lightning L402, and Stacks sBTC end-to-end flows
examples/custom-frontend.html     # Single-file zero-knowledge browser starter
notebooks/01..11_*.ipynb          # Reproducible notebooks (HIPAA, Fraud, Defense, Blind OLAP/JSONB, 4-Pillar & sklearn Suite)
cloudflare-worker-x402/           # Zero-dep Cloudflare Worker x402 v2 edge scoring proxy
contracts/base/                   # Base L2 Solidity state-root anchor (BlindCoreRootAnchor.sol)
contracts/stacks/                 # Stacks Clarity state-root anchor (blindcore-root-anchor.clar)
tools/ui_self_test.py             # Headless UI contract & security self-test harness
eval_blindcore.py                 # Live BlindCore endpoint parity & latency evaluation harness
tests/                            # Python SDK, encrypted sklearn, live ZK audit, Web ESM SDK, and UI test suites
LICENSE                           # Apache License, Version 2.0
NOTICE                            # Attribution, trademark reservation, and server-side scope notice
```

---

## Verification & Test Suite

Run the complete local verification suite with zero network calls and zero bytecode cache side effects:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests/test_sdk.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests/test_zero_check_py.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=python python3 -m blindcore.zero_check_py --domain all sklearn_blind/
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests/test_live_zero_knowledge_audit.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests/test_sklearn_blind.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests/test_ui_self_test.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest apps/test_apps_1_2.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest gate/test_trirail_gate.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest gate/test_trirail_redteam_fuzz.py
node tests/test_web_sdk.mjs
```

---

## Acknowledgments

Special thanks and a public shoutout to the **Ripwire** team for building deterministic, zero-dependency static analysis, AST lint checks, ranked symbol mapping, and structural clone/duplication detection tooling. Ripwire's zero-bloat engineering discipline directly shaped how we audit, deduplicate, and ship clean client SDKs and verification harnesses at Blind Labs.

---

## License

Licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE)). See [NOTICE](NOTICE) for attribution, trademark reservations, and proprietary server-side scope boundaries.

Copyright 2026 Blind Labs (https://blindlabs.ai).
