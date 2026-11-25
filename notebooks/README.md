# BlindCore Notebooks Index (Mode 1 Unencrypted SQL vs. Mode 2 Pure Client-Side Encrypted)

This directory contains executable Jupyter notebooks comparing **Mode 1 (Unencrypted / TLS SQL Engine, `/api/v1/query`)** against **Mode 2 (Pure Client-Side Encrypted Zero-Knowledge Compute, `/api/v1/blind/*` and `/api/v1/blind/jsonb/*`)** on live BlindCore Rust silicon.

## Cryptographic Security & Threat-Model Contract (Mode 2)

Every notebook (`01` through `09`) embeds an explicit Mode 1 vs. Mode 2 threat-model disclosure and runs a live localhost HTTP wire sniffer (`_Mode2WireSniffer` / `WireSniffProxy`) enforcing six hostile-auditor invariants:

1. **100% Client Key Custody:** Every integer leaves the client as an `80 B` IND-CPA `PLWE0001` ciphertext (`205.8x` smaller on ingress than the `16,464 B` expanded homomorphic output frame) encrypted under a client-generated `BlindClientPlweKey`. Arbitrary JSON payloads are sealed under a client-generated `BlindClientEnvelopeKey` (`SBLB0001`, `PAD2 + AES-256-GCM`, `{64..4096}` length-hiding buckets). Zero calls to `seal_values`, `seal_doc`, or `threshold_decrypt`, and zero `decrypted_aggregate` fields ever cross the wire.
2. **Zero Deterministic Binary-Class Tokens:** Binary or small-cardinality class membership (sepsis, fraud, anomaly, high-acuity, phishing, bid/ask, watch-list, WoT trust) is encoded strictly as IND-CPA `PLWE0001` `{0, 1}` and `{0, value}` indicator columns or numeric slots summed unconditionally over all rows, eliminating row-partition frequency analysis. Keyed `32 B` HMAC-SHA256 tokens (`blind_token` / `tok_slots_hex`) are restricted to high-cardinality exact-match handles with fixed dummy-padded slot counts.
3. **IND-CPA & Calibrated Shannon Entropy:** Every notebook verifies `pk.encrypt_int(42) != pk.encrypt_int(42)` and Shannon entropy `> 7.95 bits/B` over the variable ciphertext bytes `ct[40:56] + ct[60:80]` (`N = 256`).
4. **Counterfactual Wrong-Key & AEAD Tamper Knockouts:** A freshly generated wrong `BlindClientPlweKey` fails to recover the aggregate (`wrong_pk.decrypt_int != exact`), and flipping 1 bit of an `SBLB0001` ciphertext raises `ValueError`.
5. **Client-Side `NSAU0001` SHA-256 Receipt & 1-Bit Tamper Knockout:** Every homomorphic query response passes local `NSAU0001` SHA-256 receipt verification (`== True`), and flipping the LSB of `receipt_hex` deterministically fails (`== False`).
6. **Exact Zero-Error Parity:** Every Mode 2 client-decrypted aggregate (`SUM`, masked cohort `SUM`, `WEIGHTED_SUM`, sparse `CONTAINS`, `LATEST`) matches the live Mode 1 SQL plaintext oracle with `0.00e+00` error.

## Live Silicon Benchmark Matrix (`01` .. `09`)

Measured live against local `blindcore-api` with 100% raw HTTP wire capture (`0` plaintext leaks across `> 3.0 MB` total Mode 2 wire traffic, `0` execution errors, `100%` 7-bit ASCII, single-line embedded PNG figures):

| # | Notebook | Domain & Mode 2 Engine | Size | Mode 1 SQL (Ingest / Queries / Wire) | Mode 2 Client-Side Encrypted (Encrypt / Ingest / Blind Queries [Engine] / Decrypt / Wire) | Entropy (`b/B`) | Parity & Audit |
| :-: | :--- | :--- | :---: | :--- | :--- | :---: | :--- |
| 01 | `01_hospital_hipaa_sklearn_pipeline.ipynb` | Hospital ICU Sepsis Cohort (Blind OLAP) | 200 rows | `36.89 ms` / `3.21 ms` / `9.6 KB` | `268.52 ms` / `25.79 ms` / `29.83 ms` (`25.51 ms`) / `9.34 ms` / `203.0 KB` | `7.9765` | `0.00e+00`, `0` leaks / `341,708 B`, PASS |
| 02 | `02_banking_fraud_sklearn_pipeline.ipynb` | Banking Payment Fraud Ledger (Blind OLAP) | 200 rows | `44.19 ms` / `6.83 ms` / `10.1 KB` | `281.66 ms` / `28.79 ms` / `29.28 ms` (`23.52 ms`) / `7.83 ms` / `203.4 KB` | `7.9809` | `0.00e+00`, `0` leaks / `342,145 B`, PASS |
| 03 | `03_defense_telemetry_sklearn_pipeline.ipynb` | Defense UAV Sensor Telemetry (Blind OLAP) | 200 rows | `37.19 ms` / `2.62 ms` / `9.6 KB` | `227.28 ms` / `21.02 ms` / `26.61 ms` (`22.22 ms`) / `8.04 ms` / `203.2 KB` | `7.9808` | `0.00e+00`, `0` leaks / `341,923 B`, PASS |
| 04 | `04_homomorphic_blind_compute_demo.ipynb` | Hospital Claims OLAP + Blind Ridge (Blind OLAP) | 250 rows | `64.34 ms` / `3.00 ms` / `12.4 KB` | `267.59 ms` / `28.17 ms` / `35.72 ms` (`31.65 ms`) / `7.89 ms` / `253.2 KB` | `7.9790` | `0.00e+00`, `0` leaks / `393,295 B`, PASS |
| 05 | `05_blind_jsonb_nosql_demo.ipynb` | Email Security Store + Blind MNB (BlindJSONB) | 160 docs | `37.21 ms` / `3.75 ms` / `9.9 KB` | `173.29 ms` / `20.75 ms` / `14.52 ms` (`10.03 ms`) / `2.23 ms` / `260.4 KB` | `7.9814` | `0.00e+00`, `0` leaks / `304,320 B`, PASS |
| 06 | `06_agent_private_brain.ipynb` | AI Agent Private Brain (App 01 + BlindJSONB) | 160 docs | `45.86 ms` / `3.12 ms` / `10.0 KB` | `231.45 ms` / `16.93 ms` / `12.13 ms` (`9.44 ms`) / `2.43 ms` / `260.4 KB` | `7.9813` | `0.00e+00`, `0` leaks / `304,320 B`, PASS |
| 07 | `07_sealed_bid_darkpool.ipynb` | Sealed-Bid OTC Dark Pool (App 02 + Blind OLAP) | 200 rows | `37.33 ms` / `2.90 ms` / `9.4 KB` | `241.64 ms` / `23.20 ms` / `24.72 ms` (`20.63 ms`) / `9.35 ms` / `204.6 KB` | `7.9794` | `0.00e+00`, `0` leaks / `343,431 B`, PASS |
| 08 | `08_consortium_fraud_credit.ipynb` | Consortium Fraud & Credit (App 03 + Blind OLAP) | 200 rows | `40.26 ms` / `4.05 ms` / `10.6 KB` | `267.58 ms` / `23.74 ms` / `25.53 ms` (`21.34 ms`) / `9.23 ms` / `204.2 KB` | `7.9774` | `0.00e+00`, `0` leaks / `342,999 B`, PASS |
| 09 | `09_nostr_blind_relay.ipynb` | Decentralized Nostr Blind Relay (App 04 + BlindJSONB) | 160 docs | `46.32 ms` / `3.30 ms` / `9.8 KB` | `188.56 ms` / `18.21 ms` / `11.46 ms` (`8.04 ms`) / `3.16 ms` / `260.4 KB` | `7.9813` | `0.00e+00`, `0` leaks / `304,320 B`, PASS |

See also:
- `10_encrypted_storage_compression_benchmark.ipynb`: 4-pillar encrypted storage, SQL, ML, and Mode 2 client-side zero-knowledge compute benchmark suite.
- `11_encrypted_sklearn_suite_benchmark.ipynb`: Full encrypted `scikit-learn` (`sklearn_blind/`) benchmark across all `8` estimator families (`23/23` live estimators PASS vs. stock `scikit-learn 1.8.0`), live radix-packed `BlindMultinomialNB` speedup (`11.99x` E2E: `4,202.90 ms` unpacked baseline vs. `350.44 ms` packed, `Max |dP| = 5.37e-06`, `100.0%` argmax match), and hostile MITM wire audit (`185,565 B` over `11` requests, `0` leaks, `7.9782 bits/B`, `NSAU0001` + 1-bit tamper + wrong-key knockouts PASS).

## Running Locally

```bash
export BLINDCORE_URL="http://127.0.0.1:3001"
export BLINDCORE_TOKEN="<your-api-token>"
jupyter nbconvert --to notebook --execute --inplace notebooks/01_hospital_hipaa_sklearn_pipeline.ipynb
```
