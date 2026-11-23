;; BlindCoreRootAnchor (Clarity v2)
;; SPDX-License-Identifier: Apache-2.0
;; Copyright 2026 Blind Labs (https://blindlabs.ai)
;;
;; Anchors BlindCore epoch state roots and settles secp256k1-signed
;; confidential compute receipts on Stacks (Bitcoin L2), with canonical
;; sBTC SIP-010 token reference for tri-rail payment reconciliation.

;; ---------------------------------------------------------------------------
;; Constants & Error Codes
;; ---------------------------------------------------------------------------

(define-constant ERR-UNAUTHORIZED (err u100))
(define-constant ERR-STALE-EPOCH (err u101))
(define-constant ERR-ALREADY-SETTLED (err u102))
(define-constant ERR-INVALID-SIGNATURE (err u103))
(define-constant ERR-INVALID-PUBKEY (err u104))
(define-constant ERR-PUBKEY-NOT-SET (err u105))
(define-constant ERR-ZERO-HASH (err u106))
(define-constant ERR-INVALID-TIER (err u107))
(define-constant ERR-EPOCH-NOT-ANCHORED (err u108))

;; Canonical Stacks Mainnet sBTC SIP-010 fungible token contract reference:
;;   (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
;;     transfer amount sender recipient memo)
(define-constant SBTC-MAINNET-CONTRACT 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token)
(define-constant DOMAIN-TAG "BlindCoreRootAnchor-v2")
(define-constant ZERO-PUBKEY 0x000000000000000000000000000000000000000000000000000000000000000000)
(define-constant ZERO-HASH32 0x0000000000000000000000000000000000000000000000000000000000000000)
;; secp256k1 half-order (N / 2) split into two 128-bit big-endian limbs (EIP-2 / BIP-62 low-s guard)
;; N      = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
;; HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
(define-constant SECP256K1-HALF-N-HI (buff-to-uint-be 0x7fffffffffffffffffffffffffffffff))
(define-constant SECP256K1-HALF-N-LO (buff-to-uint-be 0x5d576e7357a4501ddfe92f46681b20a0))
;; secp256k1 prime field modulus P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
(define-constant SECP256K1-P-HI (buff-to-uint-be 0xffffffffffffffffffffffffffffffff))
(define-constant SECP256K1-P-LO (buff-to-uint-be 0xfffffffffffffffffffffffefffffc2f))

;; ---------------------------------------------------------------------------
;; Storage
;; ---------------------------------------------------------------------------

(define-data-var sequencer principal tx-sender)
(define-data-var pending-sequencer (optional principal) none)
(define-data-var sequencer-pubkey (buff 33) ZERO-PUBKEY)
(define-data-var sbtc-contract principal SBTC-MAINNET-CONTRACT)
(define-data-var latest-epoch uint u0)

(define-map authorized-relayers principal bool)

(define-map epoch-roots
  { epoch-seq: uint }
  {
    state-root: (buff 32),
    row-count: uint,
    anchored-height: uint
  }
)

(define-map settled-digests
  { digest: (buff 32) }
  {
    epoch-seq: uint,
    payer: principal,
    table-hash: (buff 32),
    receipt-hash: (buff 32),
    fee-sats: uint,
    op-tier: uint,
    settled-height: uint
  }
)

;; ---------------------------------------------------------------------------
;; Sequencer, Relayer & sBTC Configuration (contract-caller guarded)
;; ---------------------------------------------------------------------------

(define-public (set-sequencer-pubkey (new-pubkey (buff 33)))
  (begin
    (asserts! (is-eq contract-caller (var-get sequencer)) ERR-UNAUTHORIZED)
    (asserts! (is-eq (len new-pubkey) u33) ERR-INVALID-PUBKEY)
    (asserts! (not (is-eq new-pubkey ZERO-PUBKEY)) ERR-INVALID-PUBKEY)
    (let (
        (prefix (unwrap! (slice? new-pubkey u0 u1) ERR-INVALID-PUBKEY))
        (x-hi-buf (unwrap! (as-max-len? (unwrap! (slice? new-pubkey u1 u17) ERR-INVALID-PUBKEY) u16) ERR-INVALID-PUBKEY))
        (x-lo-buf (unwrap! (as-max-len? (unwrap! (slice? new-pubkey u17 u33) ERR-INVALID-PUBKEY) u16) ERR-INVALID-PUBKEY))
        (x-hi (buff-to-uint-be x-hi-buf))
        (x-lo (buff-to-uint-be x-lo-buf))
      )
      (asserts! (or (is-eq prefix 0x02) (is-eq prefix 0x03)) ERR-INVALID-PUBKEY)
      (asserts! (or (> x-hi u0) (> x-lo u0)) ERR-INVALID-PUBKEY)
      (asserts!
        (or
          (< x-hi SECP256K1-P-HI)
          (and (is-eq x-hi SECP256K1-P-HI) (< x-lo SECP256K1-P-LO))
        )
        ERR-INVALID-PUBKEY
      )
      (var-set sequencer-pubkey new-pubkey)
      (print { event: "sequencer-pubkey-updated", pubkey: new-pubkey })
      (ok true)
    )
  )
)

(define-public (set-sbtc-contract (new-contract principal))
  (begin
    (asserts! (is-eq contract-caller (var-get sequencer)) ERR-UNAUTHORIZED)
    (var-set sbtc-contract new-contract)
    (print { event: "sbtc-contract-updated", contract: new-contract })
    (ok true)
  )
)

(define-public (set-relayer (relayer principal) (allowed bool))
  (begin
    (asserts! (is-eq contract-caller (var-get sequencer)) ERR-UNAUTHORIZED)
    (map-set authorized-relayers relayer allowed)
    (print { event: "relayer-updated", relayer: relayer, allowed: allowed })
    (ok true)
  )
)

(define-public (propose-sequencer (next principal))
  (begin
    (asserts! (is-eq contract-caller (var-get sequencer)) ERR-UNAUTHORIZED)
    (asserts! (not (is-eq next (var-get sequencer))) ERR-UNAUTHORIZED)
    (var-set pending-sequencer (some next))
    (print { event: "sequencer-proposed", current: (var-get sequencer), next: next })
    (ok true)
  )
)

(define-public (cancel-pending-sequencer)
  (begin
    (asserts! (is-eq contract-caller (var-get sequencer)) ERR-UNAUTHORIZED)
    (let ((cancelled (var-get pending-sequencer)))
      (var-set pending-sequencer none)
      (print { event: "pending-sequencer-cancelled", cancelled: cancelled })
      (ok true)
    )
  )
)

(define-public (accept-sequencer)
  (let ((pending (unwrap! (var-get pending-sequencer) ERR-UNAUTHORIZED)))
    (asserts! (is-eq contract-caller pending) ERR-UNAUTHORIZED)
    (let ((prev (var-get sequencer)))
      (var-set sequencer pending)
      (var-set pending-sequencer none)
      ;; C-1: Fail closed by resetting sequencer-pubkey so deposed key can never settle another receipt
      (var-set sequencer-pubkey ZERO-PUBKEY)
      ;; C-4: Revoke deposed sequencer relayer access
      (map-delete authorized-relayers prev)
      (map-set authorized-relayers pending true)
      (print { event: "relayer-updated", relayer: prev, allowed: false })
      (print { event: "relayer-updated", relayer: pending, allowed: true })
      (print { event: "sequencer-accepted", previous: prev, current: pending, pubkey-reset: true })
      (ok true)
    )
  )
)

;; ---------------------------------------------------------------------------
;; Deterministic Receipt Digest (chain-id + verifying-contract domain-bound)
;; ---------------------------------------------------------------------------

(define-read-only (compute-receipt-digest
    (epoch-seq uint)
    (payer principal)
    (table-hash (buff 32))
    (receipt-hash (buff 32))
    (fee-sats uint)
    (op-tier uint)
  )
  (sha256
    (unwrap-panic
      (to-consensus-buff?
        {
          domain: DOMAIN-TAG,
          chain-id: chain-id,
          verifying-contract: (as-contract tx-sender),
          epoch-seq: epoch-seq,
          payer: payer,
          table-hash: table-hash,
          receipt-hash: receipt-hash,
          fee-sats: fee-sats,
          op-tier: op-tier
        }
      )
    )
  )
)

;; ---------------------------------------------------------------------------
;; Epoch Anchoring & Receipt Settlement
;; ---------------------------------------------------------------------------

(define-public (anchor-root (epoch-seq uint) (state-root (buff 32)) (row-count uint))
  (begin
    (asserts! (is-eq contract-caller (var-get sequencer)) ERR-UNAUTHORIZED)
    (asserts! (> epoch-seq (var-get latest-epoch)) ERR-STALE-EPOCH)
    (asserts! (is-eq (len state-root) u32) ERR-ZERO-HASH)
    (asserts! (not (is-eq state-root ZERO-HASH32)) ERR-ZERO-HASH)
    (var-set latest-epoch epoch-seq)
    (map-set epoch-roots
      { epoch-seq: epoch-seq }
      {
        state-root: state-root,
        row-count: row-count,
        anchored-height: block-height
      }
    )
    (print {
      event: "root-anchored",
      epoch-seq: epoch-seq,
      state-root: state-root,
      row-count: row-count,
      anchored-height: block-height
    })
    (ok epoch-seq)
  )
)

(define-public (settle-receipt
    (epoch-seq uint)
    (payer principal)
    (table-hash (buff 32))
    (receipt-hash (buff 32))
    (fee-sats uint)
    (op-tier uint)
    (signature (buff 65))
  )
  (let (
      (caller contract-caller)
      (pubkey (var-get sequencer-pubkey))
    )
    (asserts!
      (or
        (is-eq caller (var-get sequencer))
        (default-to false (map-get? authorized-relayers caller))
      )
      ERR-UNAUTHORIZED
    )
    (asserts! (not (is-eq pubkey ZERO-PUBKEY)) ERR-PUBKEY-NOT-SET)
    (asserts! (is-eq (len table-hash) u32) ERR-ZERO-HASH)
    (asserts! (not (is-eq table-hash ZERO-HASH32)) ERR-ZERO-HASH)
    (asserts! (is-eq (len receipt-hash) u32) ERR-ZERO-HASH)
    (asserts! (not (is-eq receipt-hash ZERO-HASH32)) ERR-ZERO-HASH)
    (asserts! (> op-tier u0) ERR-INVALID-TIER)
    (asserts! (is-some (map-get? epoch-roots { epoch-seq: epoch-seq })) ERR-EPOCH-NOT-ANCHORED)
    ;; C-3: Strict 65-byte sig, canonical v in {0x00, 0x01}, non-zero r/s, and EIP-2/BIP-62 low-s guard
    (asserts! (is-eq (len signature) u65) ERR-INVALID-SIGNATURE)
    (let (
        (sig-r (unwrap! (as-max-len? (unwrap! (slice? signature u0 u32) ERR-INVALID-SIGNATURE) u32) ERR-INVALID-SIGNATURE))
        (sig-s-hi-buf (unwrap! (as-max-len? (unwrap! (slice? signature u32 u48) ERR-INVALID-SIGNATURE) u16) ERR-INVALID-SIGNATURE))
        (sig-s-lo-buf (unwrap! (as-max-len? (unwrap! (slice? signature u48 u64) ERR-INVALID-SIGNATURE) u16) ERR-INVALID-SIGNATURE))
        (sig-v (unwrap! (as-max-len? (unwrap! (slice? signature u64 u65) ERR-INVALID-SIGNATURE) u1) ERR-INVALID-SIGNATURE))
        (sig-s-hi (buff-to-uint-be sig-s-hi-buf))
        (sig-s-lo (buff-to-uint-be sig-s-lo-buf))
      )
      (asserts! (or (is-eq sig-v 0x00) (is-eq sig-v 0x01)) ERR-INVALID-SIGNATURE)
      (asserts! (not (is-eq sig-r ZERO-HASH32)) ERR-INVALID-SIGNATURE)
      (asserts! (or (> sig-s-hi u0) (> sig-s-lo u0)) ERR-INVALID-SIGNATURE)
      (asserts!
        (or
          (< sig-s-hi SECP256K1-HALF-N-HI)
          (and (is-eq sig-s-hi SECP256K1-HALF-N-HI) (<= sig-s-lo SECP256K1-HALF-N-LO))
        )
        ERR-INVALID-SIGNATURE
      )
      (let (
          (digest (compute-receipt-digest epoch-seq payer table-hash receipt-hash fee-sats op-tier))
          (recovered (unwrap! (secp256k1-recover? digest signature) ERR-INVALID-SIGNATURE))
        )
        (asserts! (is-eq recovered pubkey) ERR-INVALID-SIGNATURE)
        (asserts!
          (map-insert settled-digests
            { digest: digest }
            {
              epoch-seq: epoch-seq,
              payer: payer,
              table-hash: table-hash,
              receipt-hash: receipt-hash,
              fee-sats: fee-sats,
              op-tier: op-tier,
              settled-height: block-height
            }
          )
          ERR-ALREADY-SETTLED
        )
        (print {
          event: "receipt-settled",
          digest: digest,
          epoch-seq: epoch-seq,
          payer: payer,
          table-hash: table-hash,
          receipt-hash: receipt-hash,
          fee-sats: fee-sats,
          op-tier: op-tier,
          sbtc-contract: (var-get sbtc-contract),
          settled-height: block-height
        })
        (ok digest)
      )
    )
  )
)

;; ---------------------------------------------------------------------------
;; Read-Only Verification Views
;; ---------------------------------------------------------------------------

(define-read-only (is-relayer (account principal))
  (or
    (is-eq account (var-get sequencer))
    (default-to false (map-get? authorized-relayers account))
  )
)

(define-read-only (is-receipt-settled (digest (buff 32)))
  (is-some (map-get? settled-digests { digest: digest }))
)

(define-read-only (get-settled-receipt (digest (buff 32)))
  (map-get? settled-digests { digest: digest })
)

(define-read-only (get-epoch-root (epoch-seq uint))
  (map-get? epoch-roots { epoch-seq: epoch-seq })
)

(define-read-only (get-sequencer)
  (var-get sequencer)
)

(define-read-only (get-sequencer-pubkey)
  (var-get sequencer-pubkey)
)

(define-read-only (get-latest-epoch)
  (var-get latest-epoch)
)

(define-read-only (get-sbtc-contract)
  (var-get sbtc-contract)
)
