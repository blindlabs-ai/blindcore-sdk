# SPDX-License-Identifier: Apache-2.0
"""Interval [lo, hi], taint algebra, and guard-dominance helpers for zero_check_py."""
from __future__ import annotations

import ast, re
from dataclasses import make_dataclass

TOP: tuple[int | None, int | None] = (None, None)
_EXITS = (ast.Return, ast.Raise, ast.Break, ast.Continue)
_FLIP = {ast.Lt: ast.GtE, ast.LtE: ast.Gt, ast.Gt: ast.LtE, ast.GtE: ast.Lt}
_REV = {ast.Lt: ast.Gt, ast.LtE: ast.GtE, ast.Gt: ast.Lt, ast.GtE: ast.LtE}
_MONO = {ast.Sub: int.__sub__, ast.RShift: int.__rshift__, ast.FloorDiv: int.__floordiv__}
_FMT = dict(B=8, b=-8, H=16, h=-16, I=32, L=32, i=-32, l=-32, Q=64, q=-64)
_CALL_IV = {"len": (0, (1 << 63) - 1), "crc32c": (0, 0xFFFFFFFF), "crc32": (0, 0xFFFFFFFF)}
_NON_INT = frozenset("self cls a vec key seed seed_a frame frames hdr aad".split())
_NON_INT_C = frozenset("bytes bytearray list dict str urandom".split())
_HASHES = frozenset("sha256 sha512 sha1 md5 sha3_256 blake2b blake2s".split())
_TAG_RX = {
    "msat": re.compile(r"(?:^|_)m?sats?(?:$|_)"),
    "money": re.compile(r"(?:^|_)(?:m?sats?|wei|gwei|lots|amount|balance)(?:$|_)"),
}
Finding = make_dataclass("Finding", [
    ("rule_id", str), ("severity", str), ("line", int), ("col", int),
    ("func", str), ("message", str), ("remediation", str), ("filename", str, "<memory>"),
], frozen=True)

def const_of(n: ast.AST, t: type):
    return n.value if isinstance(n, ast.Constant) and type(n.value) is t else None
def opt_bin(f, a, b): return f(a, b) if a is not None and b is not None else None
def width_bounds(b: int, s: bool) -> tuple[int, int]:
    return (-(1 << (b - 1)), (1 << (b - 1)) - 1) if s else (0, (1 << b) - 1)
def iv_join(a, b): return (opt_bin(min, a[0], b[0]), opt_bin(max, a[1], b[1]))
def iv_meet(a, b):
    return (b[0] if a[0] is None else (a[0] if b[0] is None else max(a[0], b[0])),
            b[1] if a[1] is None else (a[1] if b[1] is None else min(a[1], b[1])))
def dotted_name(n: ast.AST) -> str:
    if isinstance(n, ast.Attribute):
        return f"{p}.{n.attr}" if (p := dotted_name(n.value)) else n.attr
    return n.id if isinstance(n, ast.Name) else ""
def tail_name(n: ast.AST) -> str: return dotted_name(n).rsplit(".", 1)[-1]
def name_tags(s: str) -> set[str]:
    return set() if s.isupper() else {k for k, r in _TAG_RX.items() if r.search(s.lower())}
def expr_tags(n: ast.AST, taint: dict[str, set[str]]) -> set[str]:
    return {t for x in ast.walk(n) if isinstance(x, ast.Name)
            for t in (taint.get(x.id, set()) | name_tags(x.id))}
def is_non_int(n: ast.AST, non_int: set[str]) -> bool:
    if isinstance(n, ast.Name): return n.id in non_int or n.id in _NON_INT
    if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mult):
        return is_non_int(n.left, non_int) or is_non_int(n.right, non_int)
    return (isinstance(n, (ast.List, ast.ListComp, ast.Tuple, ast.Dict, ast.Set))
            or (isinstance(n, ast.Constant) and type(n.value) is not int)
            or (isinstance(n, ast.Call) and tail_name(n.func) in _NON_INT_C))
def has_unkeyed_hash(n: ast.AST) -> bool:
    return any(isinstance(x, ast.Call) and dotted_name(x.func).startswith("hashlib.")
               and tail_name(x.func) in _HASHES
               and not any(k.arg == "key" for k in x.keywords) for x in ast.walk(n))

def struct_specs(fmt: str) -> list[tuple[int, str, tuple[int, int]]]:
    out, idx = [], 0
    for m in re.finditer(r"(\d*)([xcbB?hHiIlLqQnNefdspP])", fmt):
        c, ch = int(m.group(1) or 1), m.group(2)
        if (w := _FMT.get(ch)) is not None:
            out.extend((idx + k, ch, width_bounds(abs(w), w < 0)) for k in range(c))
        idx += 0 if ch == "x" else (1 if ch in ("s", "p") else c)
    return out

def iv_binop(op: ast.operator, a, b):
    (a0, a1), (b0, b1), t = a, b, type(op)
    rok = b0 is not None and b1 is not None
    sh, pos = rok and 0 <= b0 <= b1 <= 256, rok and b0 > 0
    if t is ast.Add or (t is ast.LShift and sh and a0 is not None and a0 >= 0):
        f = int.__add__ if t is ast.Add else int.__lshift__
        return (opt_bin(f, a0, b0), opt_bin(f, a1, b1))
    if t is ast.Sub or (t is ast.RShift and sh) or (t is ast.FloorDiv and pos):
        return (opt_bin(_MONO[t], a0, b1), opt_bin(_MONO[t], a1, b0))
    if t is ast.Mult:
        if None not in (*a, *b):
            return (min(p := (a0 * b0, a0 * b1, a1 * b0, a1 * b1)), max(p))
        for c, hc, o in ((b0, b1, a), (a0, a1, b)):
            if c is not None and c == hc and c > 0:
                return (opt_bin(int.__mul__, o[0], c), opt_bin(int.__mul__, o[1], c))
    if t is ast.Mod and pos: return (0, b1 - 1)
    if t is ast.BitAnd:
        ub = [u for lo, u in (a, b) if lo is not None and u is not None and lo >= 0]
        return (0, min(ub)) if ub else TOP
    if t is ast.BitOr and a0 is not None and b0 is not None and a0 >= 0 and b0 >= 0:
        return (max(a0, b0), None if None in (a1, b1) else (1 << max(a1, b1).bit_length()) - 1)
    return TOP

def eval_interval(n: ast.AST, env: dict):
    if (v := const_of(n, int)) is not None: return (v, v)
    if isinstance(n, ast.Name): return env.get(n.id, TOP)
    if isinstance(n, ast.UnaryOp):
        lo, hi = eval_interval(n.operand, env)
        if isinstance(n.op, ast.USub):
            return (-hi if hi is not None else None, -lo if lo is not None else None)
        return (lo, hi) if isinstance(n.op, ast.UAdd) else TOP
    if isinstance(n, ast.BinOp):
        return iv_binop(n.op, eval_interval(n.left, env), eval_interval(n.right, env))
    if isinstance(n, ast.Call) and n.args:
        nm = tail_name(n.func)
        if nm in _CALL_IV: return _CALL_IV[nm]
        if nm == "int": return eval_interval(n.args[0], env)
        if nm in ("min", "max"):
            ls, hs = zip(*(eval_interval(a, env) for a in n.args))
            ol, oh = [x for x in ls if x is not None], [x for x in hs if x is not None]
            return ((min(ls) if None not in ls else None, min(oh, default=None)) if nm == "min"
                    else (max(ol, default=None), max(hs) if None not in hs else None))
        if nm == "abs":
            lo, hi = eval_interval(n.args[0], env)
            return (0, None) if None in (lo, hi) else (
                0 if lo <= 0 <= hi else min(abs(lo), abs(hi)), max(abs(lo), abs(hi)))
    return TOP

def extract_constraints(test: ast.AST, env: dict, neg: bool = False) -> dict:
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return extract_constraints(test.operand, env, not neg)
    acc: dict = {}
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or if neg else ast.And):
        for val in test.values:
            for k, iv in extract_constraints(val, env, neg).items():
                acc[k] = iv_meet(acc.get(k, TOP), iv)
    elif isinstance(test, ast.Compare) and not (neg and len(test.ops) != 1):
        for left, op, right in zip([test.left, *test.comparators], test.ops, test.comparators):
            ot = _FLIP.get(type(op)) if neg else type(op)
            for vn, ex, rev in ((left, right, False), (right, left, True)):
                if ot and isinstance(vn, ast.Name):
                    lo, hi = eval_interval(ex, env)
                    ef = _REV.get(ot, ot) if rev else ot
                    b = {ast.Lt: (None, opt_bin(int.__sub__, hi, 1)), ast.LtE: (None, hi),
                         ast.Gt: (opt_bin(int.__add__, lo, 1), None), ast.GtE: (lo, None),
                         ast.Eq: TOP if neg else (lo, hi)}.get(ef, TOP)
                    if b != TOP: acc[vn.id] = iv_meet(acc.get(vn.id, TOP), b)
    return acc

def apply_constraints(env: dict, test: ast.AST, neg: bool = False) -> dict:
    return env | {k: iv_meet(env.get(k, TOP), iv)
                  for k, iv in extract_constraints(test, env, neg).items()}
def merge_if_envs(envs: list[dict], body: list, orelse: list) -> dict:
    ex = [bool(s) and isinstance(s[-1], _EXITS) for s in (body, orelse)]
    return (envs[1] if ex[0] else envs[0]) if ex[0] != ex[1] else {
        k: iv_join(envs[0].get(k, TOP), envs[1].get(k, TOP)) for k in envs[0] | envs[1]}
def for_target_interval(it: ast.AST, env: dict, seqs: dict):
    if isinstance(it, ast.Call) and dotted_name(it.func) == "range" and it.args:
        bs = [eval_interval(x, env) for x in it.args]
        return (0 if len(bs) == 1 else bs[0][0], opt_bin(int.__sub__, bs[len(bs) > 1][1], 1))
    return seqs.get(it.id, TOP) if isinstance(it, ast.Name) else TOP
def seed_module_env(tree: ast.Module, env: dict, seqs: dict) -> None:
    for st in tree.body:
        if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(
                st.targets[0], ast.Name):
            iv, nm = eval_interval(st.value, env), st.targets[0].id
            if iv != TOP: env[nm] = iv
            elif isinstance(st.value, (ast.Tuple, ast.List)) and st.value.elts:
                vs = [v for e in st.value.elts if (v := const_of(e, int)) is not None]
                if len(vs) == len(st.value.elts): seqs[nm] = (min(vs), max(vs))
