# SPDX-License-Identifier: Apache-2.0
"""BlindCore Zero-Check Python AST Linter (zero dependencies, stdlib ast only)."""
from __future__ import annotations

import argparse, ast, json, re
from dataclasses import asdict
from pathlib import Path
try:
    from . import _ast_intervals as _iv
except ImportError:
    import _ast_intervals as _iv

Finding = _iv.Finding
U64_MAX, MAX_MSAT, PLWE_Q0, F64_SAFE = (1 << 64) - 1, 21 * 10**17, (1 << 127) - 1, 1 << 53
_SKIP = frozenset(".git __pycache__ .venv node_modules".split())
_VERBS = frozenset("do_POST do_GET do_PUT do_DELETE do_PATCH".split())
_PACK_FNS = ("struct.pack", "struct.pack_into")
_NON_INT_T = ("bytes", "str", "list", "Sequence", "dict")
_FN = (ast.FunctionDef, ast.AsyncFunctionDef)
_RULES = {
    "PY-WIDTH-01": "Add a dominating range check lo <= x <= hi before fixed-width packing.",
    "PY-MSAT-02": "Guard msat upper bound before scaling or widen explicitly to u128.",
    "PY-PLWE-03": "Prove PLWE0001 slot lies in [0, (1 << 127) - 1) before encoding.",
    "PY-FLOAT-04": "Use integer/fixed-point arithmetic or Decimal instead of float().",
    "PY-URI-05": "Validate decimal with re.fullmatch and split ?query/#fragment via urlsplit.",
    "PY-CRYPTO-06": "Use hmac.new(key, msg, hashlib.sha256) instead of unkeyed hashlib.",
    "PY-TIMING-07": "Use hmac.compare_digest(a, b) for constant-time secret comparison.",
    "PY-CSRF-08": "Validate Host against an allowlist and reject cross-site Origin headers.",
    "PY-MERKLE-09": "Promote odd Merkle leaves with domain tags; use (3 * d) ^ 2 Hensel seeds.",
}
_RX = {k: re.compile(v if k[0] == "_" else rf"(?:^|_)(?:{v})(?:$|_)") for k, v in (
    ("mac", "mac|hmac|receipt|sig|signature|auth_tag"), ("_hns", r"hensel|modinv|inv|mont"),
    ("sec", "token|mac|hmac|digest|sig|signature|tag|secret|api_key"),
    ("pfn", "ip|ipv4|host|port|amount|uri|url|addr"), ("uri", "path|url|uri|base_url|endpoint"),
    ("seg", "seg|segment|rel|suffix|subpath|target|route"),
    ("_parg", r"^(?:oct|octet|part|seg|port|amount|raw_amount|amt|host_part|m?sats?|wei)$"),
    ("_plwe", r"(?:^|_)(?:pack|encode|seal|encrypt)_?plwe|plwe_?(?:slot|pack|encode|encrypt)"),
    ("_mrk", r"merkle|tree|level|leaf|leaves|nodes|hashes|layer"),
)}

def _fn_flags(fn: ast.AST) -> tuple[bool, bool, bool]:
    ns = list(ast.walk(fn))
    nms = {_iv.tail_name(n.func) for n in ns if isinstance(n, ast.Call)}
    ss = {s for n in ns if (s := _iv.const_of(n, str)) is not None}
    nw = any(isinstance(n, ast.BinOp) and isinstance(n.op, ast.Sub)
             and _iv.const_of(n.left, int) == 2 and isinstance(n.right, ast.BinOp)
             and isinstance(n.right.op, ast.Mult) for n in ns)
    zs = bool(nms & {"startswith", "isascii", "strip"} or ss & {"0", "+"})
    return (bool(nms & {"fullmatch", "match"} or (nms & {"isdigit", "isdecimal"} and zs)),
            bool(nms & {"urlsplit", "urlparse", "urldefrag"}) or {"?", "#"} <= ss, nw)

class _Visitor(ast.NodeVisitor):
    def __init__(self, domain: str, filename: str) -> None:
        self.domain, self.filename, self.func = domain, filename, "<module>"
        self.findings, self.env, self.seqs, self.taint = [], {}, {}, {}
        self.non_int, self._xor2, self._flags, self._u128 = set(), set(), (0, 0, 0), False
    def _ev(self, e: ast.AST): return _iv.eval_interval(e, self.env)
    def _tg(self, e: ast.AST) -> set[str]: return _iv.expr_tags(e, self.taint)
    def _add(self, n: ast.AST, rid: str, msg: str) -> None:
        sev = "CRITICAL" if rid == "PY-MERKLE-09" else "HIGH"
        self.findings.append(Finding(rid, sev, getattr(n, "lineno", 1),
            getattr(n, "col_offset", 0), self.func, msg, _RULES[rid], self.filename))
    def _bounds(self, n: ast.AST, ex: ast.AST, lb: int, hb: int, rid: str, lbl: str):
        lo, hi = self._ev(ex)
        if lo is None or hi is None or lo < lb or hi > hb:
            self._add(n, rid, f"{lbl} interval [{lo}, {hi}] not proven in [{lb}, {hb}]")
    def visit(self, n: ast.AST) -> None:
        if isinstance(n, _FN):
            sv = (self.func, dict(self.env), {k: set(v) for k, v in self.taint.items()},
                  set(self.non_int), self._flags)
            self.func, self._flags = n.name, _fn_flags(n)
            for a in (*n.args.posonlyargs, *n.args.args, *n.args.kwonlyargs):
                self.env[a.arg], self.taint[a.arg] = _iv.TOP, _iv.name_tags(a.arg)
                if a.annotation and any(t in ast.unparse(a.annotation) for t in _NON_INT_T):
                    self.non_int.add(a.arg)
            for st in n.body: self.visit(st)
            self.func, self.env, self.taint, self.non_int, self._flags = sv
            return
        if isinstance(n, ast.If):
            self.visit(n.test)
            base, envs = dict(self.env), []
            for br, neg in ((n.body, False), (n.orelse, True)):
                self.env = _iv.apply_constraints(base, n.test, neg)
                for st in br: self.visit(st)
                envs.append(dict(self.env))
            self.env = _iv.merge_if_envs(envs, n.body, n.orelse)
            return
        if isinstance(n, ast.For):
            self.visit(n.iter)
            if isinstance(n.target, ast.Name):
                self.env[n.target.id] = _iv.for_target_interval(n.iter, self.env, self.seqs)
            for st in (*n.body, *n.orelse): self.visit(st)
            return
        if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None:
            tgts = n.targets if isinstance(n, ast.Assign) else [n.target]
            prev, self._u128 = self._u128, self._u128 or any(
                isinstance(t, ast.Name) and "u128" in t.id.lower() for t in tgts)
            self.visit(n.value)
            self._u128 = prev
            iv, tg = self._ev(n.value), self._tg(n.value)
            ni, uk = _iv.is_non_int(n.value, self.non_int), _iv.has_unkeyed_hash(n.value)
            for t in tgts:
                if isinstance(t, ast.Name):
                    self.env[t.id], self.taint[t.id] = iv, tg | _iv.name_tags(t.id)
                    (self.non_int.add if ni else self.non_int.discard)(t.id)
                    if uk and _RX["mac"].search(t.id.lower()):
                        self._add(n.value, "PY-CRYPTO-06", f"Unkeyed hash to `{t.id}`")
            return
        if isinstance(n, ast.AugAssign):
            self.visit(n.value)
            if isinstance(n.target, ast.Name):
                k = n.target.id
                self.env[k] = _iv.iv_binop(n.op, self.env.get(k, _iv.TOP), self._ev(n.value))
                self.taint.setdefault(k, set()).update(self._tg(n.value))
            return
        if isinstance(n, ast.Return) and n.value is not None:
            self.visit(n.value)
            if _RX["mac"].search(self.func.lower()) and _iv.has_unkeyed_hash(n.value):
                self._add(n.value, "PY-CRYPTO-06", f"Unkeyed hash from `{self.func}`")
            return
        if isinstance(n, ast.Assert):
            self.visit(n.test)
            self.env = _iv.apply_constraints(self.env, n.test)
            return
        if isinstance(n, ast.ClassDef) and any(
                _iv.tail_name(b) == "BaseHTTPRequestHandler" for b in n.bases):
            ms = {m.name: m for m in n.body if isinstance(m, _FN)}
            ho = {k for k, f in ms.items() if any((s := _iv.const_of(x, str))
                  and s.lower() in ("host", "origin") for x in ast.walk(f))}
            for nm, fn in ms.items():
                if nm in _VERBS and not ({nm} | {c.func.attr for c in ast.walk(fn)
                    if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
                    and _iv.dotted_name(c.func.value) == "self"}) & ho:
                    self._add(fn, "PY-CSRF-08", f"{n.name}.{nm} lacks Host/Origin check")
        elif isinstance(n, ast.Compare):
            for l, op, r in zip([n.left, *n.comparators], n.ops, n.comparators):
                if (isinstance(op, (ast.Eq, ast.NotEq))
                    and not any(isinstance(x, ast.Constant)
                        and not (isinstance(x.value, (str, bytes)) and x.value) for x in (l, r))
                    and any(_RX["sec"].search(_iv.tail_name(x).lower())
                        for x in (l, r) if isinstance(x, (ast.Name, ast.Attribute)))):
                    self._add(n, "PY-TIMING-07", "Non-constant-time equality check on secret")
        elif isinstance(n, ast.BinOp): self._binop(n)
        elif isinstance(n, ast.Call) and self._call(n): return
        self.generic_visit(n)
    def _binop(self, n: ast.BinOp) -> None:
        if isinstance(n.op, ast.BitXor):
            self._xor2 |= {id(o) for c, o in ((n.right, n.left), (n.left, n.right))
                           if _iv.const_of(c, int) == 2}
        if isinstance(n.op, ast.Mult):
            if self.domain in ("bitcoin", "all") and not self._u128:
                lt, rt = self._tg(n.left), self._tg(n.right)
                if "msat" in lt or "msat" in rt:
                    lh, rh = self._ev(n.left)[1], self._ev(n.right)[1]
                    el = lh if lh is not None else (MAX_MSAT if "msat" in lt else None)
                    er = rh if rh is not None else (MAX_MSAT if "msat" in rt else None)
                    if el is None or er is None or el * er > U64_MAX:
                        self._add(n, "PY-MSAT-02", "Bitcoin/LN msat mul exceeds UINT64_MAX")
            if (id(n) not in self._xor2
                and (_RX["_hns"].search(self.func.lower()) or self._flags[2])
                and any(_iv.const_of(c, int) == 3 and isinstance(o, ast.Name)
                        for c, o in ((n.left, n.right), (n.right, n.left)))):
                self._add(n, "PY-MERKLE-09", "Hensel seed `3 * d` missing `^ 2`")
        if isinstance(n.op, ast.Add) and not self._flags[1]:
            lnm, rnm = _iv.tail_name(n.left).lower(), _iv.tail_name(n.right).lower()
            if _RX["uri"].search(lnm) and isinstance(n.right, ast.Name) and (
                    _RX["seg"].search(rnm) or not rnm.startswith("_")):
                self._add(n, "PY-URI-05", f"Manual URI join `{lnm}+{rnm}` without ?/# split")
    def _call(self, n: ast.Call) -> bool:
        full, short, args = _iv.dotted_name(n.func), _iv.tail_name(n.func), n.args
        defi, fn_low = self.domain in ("defi", "all"), self.func.lower()
        if short in ("u128", "to_u128", "checked_mul_u128"):
            prev, self._u128 = self._u128, True
            self.generic_visit(n)
            self._u128 = prev
            return True
        if full in _PACK_FNS and args and (fmt := _iv.const_of(args[0], str)):
            vargs = args[3:] if short == "pack_into" else args[1:]
            for idx, ch, (lb, hb) in _iv.struct_specs(fmt):
                if idx < len(vargs):
                    self._bounds(n, vargs[idx], lb, hb, "PY-WIDTH-01", f"struct.pack({ch!r})")
        elif isinstance(n.func, ast.Attribute) and short == "to_bytes" and args:
            lo, hi = self._ev(args[0])
            if lo is not None and lo == hi and 1 <= lo <= 32:
                sgn = any(k.arg == "signed" and getattr(k.value, "value", 0) is True
                          for k in n.keywords)
                vnm = _iv.dotted_name(n.func.value).lower()
                if defi and lo == 16 and ("plwe" in fn_low or "plwe" in vnm or "slot" in vnm):
                    self._bounds(n, n.func.value, 0, PLWE_Q0 - 1, "PY-PLWE-03", "PLWE slot")
                else:
                    lb, hb = _iv.width_bounds(8 * lo, sgn)
                    self._bounds(n, n.func.value, lb, hb, "PY-WIDTH-01", f"to_bytes({lo})")
        elif defi and _RX["_plwe"].search(short.lower()):
            for a in args:
                if not _iv.is_non_int(a, self.non_int):
                    self._bounds(n, a, 0, PLWE_Q0 - 1, "PY-PLWE-03", f"PLWE `{short}` slot")
        elif defi and short == "float" and args and ({"money", "msat"} & self._tg(args[0])):
            lo, hi = self._ev(args[0])
            if lo is None or hi is None or lo < -F64_SAFE or hi > F64_SAFE:
                self._add(n, "PY-FLOAT-04", "float() on monetary int loses precision > 2^53")
        elif short == "int" and args and not self._flags[0] and self._ev(args[0]) == _iv.TOP:
            if _RX["pfn"].search(fn_low) or _RX["_parg"].search(_iv.tail_name(args[0]).lower()):
                self._add(n, "PY-URI-05", "Unvalidated int() accepts '+', whitespace, octal")
        elif short == "urljoin" and not self._flags[1]:
            self._add(n, "PY-URI-05", "urljoin() can smuggle or drop ?query/#fragment")
        elif isinstance(n.func, ast.Attribute) and short == "append" and len(args) == 1:
            seq = n.func.value
            if (isinstance(seq, ast.Name) and ast.unparse(args[0]) == f"{seq.id}[-1]"
                    and (_RX["_mrk"].search(fn_low) or _RX["_mrk"].search(seq.id.lower()))):
                self._add(n, "PY-MERKLE-09", f"Odd-leaf Merkle dup `{seq.id}.append(...)`")
        return False

def check_ast_module(src: str, domain="bitcoin", filename="<memory>") -> list[Finding]:
    if domain not in ("bitcoin", "defi", "all"):
        raise ValueError(f"unsupported domain {domain!r}; expected 'bitcoin', 'defi', or 'all'")
    tree, vis = ast.parse(src, filename=filename), _Visitor(domain, filename)
    _iv.seed_module_env(tree, vis.env, vis.seqs)
    vis.visit(tree)
    return vis.findings
def check_ast_path(path: str | Path, domain: str = "bitcoin") -> list[Finding]:
    p = Path(path)
    fs = [p] if p.is_file() else [c for c in sorted(p.rglob("*.py")) if not _SKIP & set(c.parts)]
    return [f for c in fs for f in check_ast_module(c.read_text("utf-8"), domain, str(c))]
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="blindcore.zero_check_py")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--domain", choices=("bitcoin", "defi", "all"), default="all")
    ap.add_argument("--json", action="store_true", dest="as_json")
    ns = ap.parse_args(argv)
    res = [f for raw in ns.paths for f in check_ast_path(raw, ns.domain)]
    out = [json.dumps([asdict(f) for f in res], indent=2)] if ns.as_json else [
        f"{f.filename}:{f.line}:{f.col} [{f.severity}] {f.rule_id} ({f.func}): {f.message}"
        for f in res]
    if out: print("\n".join(out))
    return int(bool(res))
if __name__ == "__main__":
    raise SystemExit(main())
