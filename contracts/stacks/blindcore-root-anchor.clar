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
  (let ((prefix (unwrap! (slice? new-pubkey u0 u1) ERR-INVALID-PUBKEY)))
    (asserts! (is-eq contract-caller (var-get sequencer)) ERR-UNAUTHORIZED)
    (asserts! (is-eq (len new-pubkey) u33) ERR-INVALID-PUBKEY)
    (asserts! (not (is-eq new-pubkey ZERO-PUBKEY)) ERR-INVALID-PUBKEY)
    (asserts! (or (is-eq prefix 0x02) (is-eq prefix 0x03)) ERR-INVALID-PUBKEY)
    (var-set sequencer-pubkey new-pubkey)
    (print { event: "sequencer-pubkey-updated", pubkey: new-pubkey })
    (ok true)
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
      (map-set authorized-relayers pending true)
      (print { event: "sequencer-accepted", previous: prev, current: pending })
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
    (asserts! (not (is-eq table-hash ZERO-HASH32)) ERR-ZERO-HASH)
    (asserts! (not (is-eq receipt-hash ZERO-HASH32)) ERR-ZERO-HASH)
    (asserts! (> op-tier u0) ERR-INVALID-TIER)
    (asserts! (is-some (map-get? epoch-roots { epoch-seq: epoch-seq })) ERR-EPOCH-NOT-ANCHORED)
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
