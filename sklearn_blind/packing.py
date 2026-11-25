"""Radix-B SIMD slot packing and noise-budget guards for Depth-0 PLWE0001."""

from __future__ import annotations

from typing import Sequence

from python.blindcore_sdk import LWE_PLAIN_MOD, LWE_Q0

MAX_SIGNED_PLAIN = LWE_PLAIN_MOD // 2
MAX_I64_WEIGHT = (1 << 63) - 1
MAX_NOISE_UNITS = LWE_Q0 // (2 * LWE_PLAIN_MOD)


def check_weighted_sum_noise(n_rows: int, weights: Sequence[int]) -> None:
    """Verify PLWE0001 Depth-0 exact decryption noise budget and i64 weight bounds."""
    n = int(n_rows)
    if n < 1:
        raise ValueError("n_rows must be >= 1")
    if not weights:
        raise ValueError("weights must be non-empty")
    l1 = 0
    for w in weights:
        wi = int(w)
        if abs(wi) >= MAX_I64_WEIGHT:
            raise ValueError(f"weight |{wi}| exceeds signed i64 bound {MAX_I64_WEIGHT}")
        l1 += abs(wi)
    if 4 * n * l1 >= MAX_NOISE_UNITS:
        raise ValueError(
            f"WEIGHTED_SUM noise budget exceeded: 4 * {n} * {l1} >= {MAX_NOISE_UNITS}"
        )


class RadixSlotPacker:
    """Pack K integer slots into one signed PLWE0001 plaintext via base B = 2^b.

    Unsigned mode (signed=False):
      - Valid slot range: 0 <= s_k < B
      - Invariant: B**K <= LWE_PLAIN_MOD // 2
    Signed mode (signed=True, balanced centered remainder):
      - Valid slot range: -(B // 2) < s_k < (B // 2), i.e. |s_k| <= B // 2 - 1
      - Invariant: B**K <= LWE_PLAIN_MOD // 2
      - Unpacks with centered remainder: r = v % B; if r >= B // 2: r -= B; v = (v - r) // B
    """

    def __init__(self, n_slots: int, base_bits: int, signed: bool = False) -> None:
        k = int(n_slots)
        b_bits = int(base_bits)
        if k < 1:
            raise ValueError("n_slots must be >= 1")
        min_bits = 3 if signed else 2
        if b_bits < min_bits:
            raise ValueError(f"base_bits must be >= {min_bits} (got {b_bits})")
        base = 1 << b_bits
        capacity = base**k
        if capacity > MAX_SIGNED_PLAIN:
            raise ValueError(
                f"radix capacity B**K = 2**({b_bits}*{k}) exceeds LWE_PLAIN_MOD // 2"
            )
        self.n_slots = k
        self.base_bits = b_bits
        self.signed = bool(signed)
        self.base = base
        self.half = base // 2
        self.max_abs = (self.half - 1) if self.signed else (base - 1)
        self.capacity = capacity
        self._powers = tuple(base**i for i in range(k))

    def pack(self, slots: Sequence[int]) -> int:
        """Pack exactly n_slots integers into one signed PLWE0001 plaintext."""
        if len(slots) != self.n_slots:
            raise ValueError(f"expected {self.n_slots} slots, got {len(slots)}")
        acc = 0
        if self.signed:
            lim = self.max_abs
            for val, pwr in zip(slots, self._powers):
                iv = int(val)
                if iv < -lim or iv > lim:
                    raise ValueError(f"signed slot {iv} out of range [-{lim}, {lim}]")
                acc += iv * pwr
        else:
            b = self.base
            for val, pwr in zip(slots, self._powers):
                iv = int(val)
                if iv < 0 or iv >= b:
                    raise ValueError(f"unsigned slot {iv} out of range [0, {b - 1}]")
                acc += iv * pwr
        if abs(acc) > MAX_SIGNED_PLAIN:
            raise ValueError(f"packed integer {acc} exceeds LWE_PLAIN_MOD // 2")
        return acc

    def unpack(self, packed: int) -> list[int]:
        """Unpack one decrypted PLWE0001 integer into n_slots integers with carry checks."""
        v = int(packed)
        b = self.base
        out: list[int] = []
        if self.signed:
            half = self.half
            lim = self.max_abs
            for _ in range(self.n_slots):
                r = v % b
                if r >= half:
                    r -= b
                if r < -lim or r > lim:
                    raise ValueError(f"signed slot overflow: {r} outside [-{lim}, {lim}]")
                out.append(r)
                v = (v - r) // b
            if v != 0:
                raise ValueError(f"signed radix carry overflow: residual={v}")
            return out
        if v < 0 or v >= self.capacity:
            raise ValueError(f"unsigned packed value {v} out of range [0, {self.capacity - 1}]")
        for _ in range(self.n_slots):
            out.append(v % b)
            v //= b
        return out


def choose_unsigned_packer(max_slot_sum: int, n_values: int) -> RadixSlotPacker:
    """Choose the widest valid unsigned RadixSlotPacker for max_slot_sum."""
    if max_slot_sum < 0:
        raise ValueError("max_slot_sum must be non-negative")
    b_bits = max(2, int(max_slot_sum).bit_length())
    if (1 << b_bits) <= max_slot_sum:
        b_bits += 1
    if b_bits > 58:
        raise ValueError(f"max_slot_sum={max_slot_sum} exceeds 58-bit plaintext headroom")
    max_k = min(max(1, int(n_values)), 58 // b_bits)
    while max_k > 1 and (1 << (b_bits * max_k)) > MAX_SIGNED_PLAIN:
        max_k -= 1
    return RadixSlotPacker(n_slots=max_k, base_bits=b_bits, signed=False)


def choose_signed_packer(max_abs_slot: int, n_values: int) -> RadixSlotPacker:
    """Choose the widest valid signed balanced-remainder RadixSlotPacker."""
    if max_abs_slot < 0:
        raise ValueError("max_abs_slot must be non-negative")
    b_bits = max(3, int(max_abs_slot).bit_length() + 1)
    if (1 << (b_bits - 1)) - 1 < max_abs_slot:
        b_bits += 1
    if b_bits > 58:
        raise ValueError(f"max_abs_slot={max_abs_slot} exceeds 57-bit signed headroom")
    max_k = min(max(1, int(n_values)), 58 // b_bits)
    while max_k > 1 and (1 << (b_bits * max_k)) > MAX_SIGNED_PLAIN:
        max_k -= 1
    return RadixSlotPacker(n_slots=max_k, base_bits=b_bits, signed=True)
