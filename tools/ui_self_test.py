#!/usr/bin/env python3
"""
Blind Labs Permanent UI Contract Self-Test Harness.

Drives real headless Chromium via Playwright across Blind Labs web surfaces
(/social/, /sign/, /mail/, /finance/, or a single local surface '/') and exits
non-zero on ANY contract failure:
  - HTTP status != 200 or any failed network request (HTTP >= 400)
  - Any runtime pageerror or console.error
  - Duplicate hoisted JS function definitions in inline <script> blocks
  - Any broken, erroring, or dead visible button across all discovered tabs
  - Any desktop (1440x900) or mobile (390x844) horizontal overflow, orphan
    button wrap, clipped button text, broken image, or unhydrated placeholder
  - Create New Account (#newIdentityBtn) counterfactual failure (identity must
    rotate cleanly with zero errors and a hydrated non-empty vault key)
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_BASE_URL = os.environ.get("BLINDLABS_BASE_URL", "http://127.0.0.1:8080")
SURFACE_ALIASES: Dict[str, str] = {
    "social": "/social/",
    "sign": "/sign/",
    "mail": "/mail/",
    "finance": "/finance/",
}

JARGON_PATTERNS: List[Tuple[str, str]] = [
    ("WebCrypto", r"\bWebCrypto\b"),
    ("P-256", r"\bP-256\b"),
    ("ECDSA", r"\bECDSA\b"),
    ("ECDH/ecdh_", r"\bECDH\b|ecdh_"),
    ("Self-sovereign", r"Self-sovereign|self-sovereign"),
    ("AES-GCM/AES-256", r"\bAES-(?:GCM|256(?:-GCM)?)\b"),
    ("HKDF/PBKDF2/Argon2", r"\b(?:HKDF|PBKDF2|Argon2)\b"),
    ("JWK", r"\bJWK\b"),
    ("pubkey", r"\bpubkey\b|pubkey_id"),
    ("ciphertext", r"\bciphertext\b"),
    ("keypair/provisioned", r"\b(?:keypair|provisioned)\b"),
    ("O(1)/shred", r"\bO\(1\)|\bshred(?:ded)?\b"),
    ("Ed25519/X25519/RSA/SHA-256", r"\b(?:Ed25519|X25519|RSA-\d+|SHA-256|secp256k1)\b"),
    ("raw_hex_id", r"\b(?:bf_[0-9a-f]{8,}|0x[0-9a-fA-F]{12,}|[0-9a-f]{24,})\b"),
    ("node_handle", r"\bnode_[0-9a-f]{4,}\b"),
    ("Epoch_jargon", r"\bEpoch\s*\d+|\(E\d+\)"),
    ("relay_jargon", r"\b(?:the relay|relay shred|blind relay)\b"),
    ("crypto.subtle", r"crypto\.subtle"),
]

INIT_HOOK_JS = """
(() => {
  window.__selftest_events = [];
  const origAnchorClick = HTMLAnchorElement.prototype.click;
  HTMLAnchorElement.prototype.click = function(...args) {
    window.__selftest_events.push({
      type: 'anchor_click',
      download: this.download || '',
      href: (this.href || '').slice(0, 80)
    });
    return origAnchorClick.apply(this, args);
  };
  const origInputClick = HTMLInputElement.prototype.click;
  HTMLInputElement.prototype.click = function(...args) {
    window.__selftest_events.push({
      type: 'input_click',
      inputType: this.type || '',
      id: this.id || ''
    });
    if (this.type === 'file') return;
    return origInputClick.apply(this, args);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    const origCopy = navigator.clipboard.writeText.bind(navigator.clipboard);
    navigator.clipboard.writeText = async function(txt) {
      window.__selftest_events.push({type: 'clipboard_write', len: String(txt || '').length});
      try { return await origCopy(txt); } catch (_e) { return; }
    };
  }
  const origFocus = HTMLElement.prototype.focus;
  HTMLElement.prototype.focus = function(...args) {
    window.__selftest_events.push({type: 'focus', tag: this.tagName, id: this.id || ''});
    return origFocus.apply(this, args);
  };
  const origPrint = window.print;
  window.print = function() {
    window.__selftest_events.push({type: 'window_print'});
  };
  document.addEventListener('invalid', (ev) => {
    const t = ev.target;
    window.__selftest_events.push({
      type: 'html5_invalid',
      id: (t && t.id) || '',
      name: (t && t.name) || ''
    });
  }, true);
})();
"""


def find_chrome(explicit: Optional[str] = None) -> Optional[str]:
    if explicit:
        return explicit if os.path.exists(explicit) else None
    candidates = [
        os.environ.get("CHROME_BIN", ""),
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ]
    home = os.path.expanduser("~")
    candidates.extend(sorted(glob.glob(os.path.join(home, ".cache/ms-playwright/chromium-*/chrome-linux*/chrome")), reverse=True))
    for c in candidates:
        if c and os.path.exists(c):
            return c
    return None


def parse_surfaces(raw_items: List[str]) -> List[str]:
    out: List[str] = []
    for item in raw_items:
        for part in item.split(","):
            s = part.strip()
            if not s:
                continue
            if s.lower() in SURFACE_ALIASES:
                norm = SURFACE_ALIASES[s.lower()]
            elif s.startswith("/"):
                norm = s
            else:
                norm = "/" + s.strip("/") + "/"
            if norm not in out:
                out.append(norm)
    return out or list(SURFACE_ALIASES.values())


def hash_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()[:16]


def find_duplicate_js_functions(html: str) -> List[Dict[str, Any]]:
    """Detect duplicate hoisted `function foo(` definitions at top-level or outer-IIFE scope."""
    dupes: List[Dict[str, Any]] = []
    scripts = re.findall(r"<script[^>]*>([\s\S]*?)</script>", html, flags=re.IGNORECASE)
    for si, script in enumerate(scripts):
        seen: Dict[str, List[int]] = {}
        depth = 0
        for lineno, line in enumerate(script.splitlines(), 1):
            stripped = line.lstrip()
            if depth <= 1:
                m = re.match(r"^(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(", stripped)
                if m:
                    fn = m.group(1)
                    seen.setdefault(fn, []).append(lineno)
            clean = re.sub(r"(['\"`])(?:\\.|(?!\1).)*\1", "", line)
            clean = re.sub(r"//.*$", "", clean)
            depth = max(0, depth + clean.count("{") - clean.count("}"))
        for fn, lines in seen.items():
            if len(lines) > 1:
                dupes.append({"script_index": si, "function": fn, "script_lines": lines})
    return dupes


def scan_jargon(text: str, source: str, allow_dns_dkim: bool = False) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    filtered_text = text
    if allow_dns_dkim:
        filtered_text = re.sub(r"v=DKIM1;[^\n]*", "", filtered_text)
    for label, pat in JARGON_PATTERNS:
        flags = 0 if label in ("JWK", "ECDSA", "P-256", "WebCrypto", "AES-GCM/AES-256") else re.IGNORECASE
        matches = list(re.finditer(pat, filtered_text, flags=flags))
        if matches:
            samples: List[str] = []
            for m in matches[:3]:
                s = max(0, m.start() - 25)
                e = min(len(filtered_text), m.end() + 25)
                snippet = re.sub(r"\s+", " ", filtered_text[s:e]).strip()
                if snippet not in samples:
                    samples.append(snippet)
            hits.append({
                "source": source,
                "category": label,
                "count": len(matches),
                "samples": samples,
            })
    return hits


def scan_script_user_strings(html: str) -> List[Dict[str, Any]]:
    """Check confirm(), alert(), prompt(), and showToast() calls in inline JS for programmer jargon."""
    scripts = "\n".join(re.findall(r"<script[^>]*>([\s\S]*?)</script>", html, flags=re.IGNORECASE))
    user_strings: List[str] = []
    for m in re.finditer(r'\b(?:confirm|alert|prompt|showToast|toast)\s*\(\s*(["\'])((?:\\.|(?!\1).)*)\1', scripts):
        user_strings.append(m.group(0))
    return scan_jargon("\n".join(user_strings), "js_dialogs_toasts")


def dom_snapshot(page: Any) -> Dict[str, Any]:
    return page.evaluate("""() => {
        const text = document.body ? (document.body.innerText || '') : '';
        const nodes = [...document.querySelectorAll('body *')].map(el => {
            const st = el.style ? el.style.display : '';
            const cls = typeof el.className === 'string' ? el.className : '';
            const vis = el.offsetParent !== null ? '1' : '0';
            return el.tagName + '#' + (el.id || '') + '.' + cls + ':' + vis + ':' + st;
        }).join(';');
        const inputs = [...document.querySelectorAll('input, textarea, select')].map(el =>
            (el.id || el.name || el.type) + '=' + (el.type === 'checkbox' || el.type === 'radio' ? el.checked : (el.value || '').slice(0, 60))
        ).join('|');
        const activeClasses = [...document.querySelectorAll('.active, [aria-selected="true"], .btn-primary, .active-public, .active-private')].map(el =>
            el.tagName + '#' + el.id + ':' + (el.innerText || '').trim().slice(0, 24)
        ).join('|');
        const ls = {};
        try {
            for (let i = 0; i < localStorage.length; i++) {
                const k = localStorage.key(i);
                const v = localStorage.getItem(k) || '';
                ls[k] = v.length + ':' + v.slice(0, 120);
            }
        } catch (_e) {}
        const toastEl = document.querySelector('#toast, .toast, [role="status"], [role="alert"]');
        const toastText = toastEl ? (toastEl.innerText || '').trim() : '';
        const events = (window.__selftest_events || []).slice();
        return {
            dom_sig: nodes + '||' + text,
            text_len: text.length,
            inputs: inputs,
            active: activeClasses,
            ls: JSON.stringify(ls),
            toast: toastText,
            url: location.href,
            events_count: events.length,
            events: events,
            theme: document.documentElement.getAttribute('data-theme') || document.body.className || '',
        };
    }""")


def check_layout(page: Any, view_name: str, viewport_label: str) -> Dict[str, Any]:
    return page.evaluate("""([viewName, vpLabel]) => {
        const issues = [];
        const docW = document.documentElement.scrollWidth;
        const winW = window.innerWidth;
        if (docW > winW + 2) {
            issues.push({
                type: 'horizontal_overflow',
                view: viewName,
                viewport: vpLabel,
                detail: `scrollWidth=${docW} > innerWidth=${winW} (+${docW - winW}px)`
            });
        }

        const containers = [...document.querySelectorAll('div, nav, header, footer, section, form')];
        const seenContainers = new Set();
        for (const c of containers) {
            if (c.offsetParent === null) continue;
            const directBtns = [...c.children].filter(ch =>
                (ch.tagName === 'BUTTON' || (ch.tagName === 'A' && ch.classList.contains('btn'))) &&
                ch.offsetParent !== null
            );
            if (directBtns.length >= 3) {
                const style = getComputedStyle(c);
                if (style.display.includes('flex') && style.flexDirection !== 'column') {
                    const rows = [];
                    for (const b of directBtns) {
                        const r = b.getBoundingClientRect();
                        if (r.width === 0 || r.height === 0) continue;
                        let placed = false;
                        for (const row of rows) {
                            if (Math.abs(row.top - r.top) < 10) {
                                row.items.push((b.innerText || b.id || '').trim().replace(/\\s+/g, ' ').slice(0, 30));
                                placed = true;
                                break;
                            }
                        }
                        if (!placed) {
                            rows.push({top: r.top, items: [(b.innerText || b.id || '').trim().replace(/\\s+/g, ' ').slice(0, 30)]});
                        }
                    }
                    if (rows.length >= 2) {
                        const counts = rows.map(r => r.items.length);
                        const key = counts.join('+') + ':' + rows.map(r => r.items.join(',')).join('|');
                        if (!seenContainers.has(key) && counts[counts.length - 1] === 1 && counts[0] >= 2) {
                            seenContainers.add(key);
                            issues.push({
                                type: 'orphan_button_wrap',
                                view: viewName,
                                viewport: vpLabel,
                                detail: `Row split ${counts.join('+')}: ${rows.map(r => '[' + r.items.join(', ') + ']').join(' / ')}`
                            });
                        }
                    }
                }
            }
        }

        const visibleBtns = [...document.querySelectorAll('button, a.btn')].filter(el => el.offsetParent !== null);
        for (const b of visibleBtns) {
            if (b.scrollWidth > b.clientWidth + 4 && getComputedStyle(b).overflow === 'hidden') {
                issues.push({
                    type: 'clipped_button_text',
                    view: viewName,
                    viewport: vpLabel,
                    detail: `Button "${(b.innerText || '').trim().slice(0, 35)}" scrollW=${b.scrollWidth} > clientW=${b.clientWidth}`
                });
            }
        }
        const imgs = [...document.querySelectorAll('img')].filter(img => img.offsetParent !== null);
        for (const img of imgs) {
            if (img.complete && img.naturalWidth === 0) {
                issues.push({
                    type: 'broken_image',
                    view: viewName,
                    viewport: vpLabel,
                    detail: `src=${img.src}`
                });
            }
        }

        const placeholders = [...document.querySelectorAll('.mono-box, [id*="Pubkey"], [id*="Ecdh"], [id*="Fingerprint"], [id*="Address"], [id*="Account"]')].filter(el => el.offsetParent !== null);
        for (const el of placeholders) {
            const t = (el.innerText || '').trim();
            if (t === '-' || t === 'Loading...' || t === 'undefined' || t === 'null') {
                issues.push({
                    type: 'unhydrated_placeholder',
                    view: viewName,
                    viewport: vpLabel,
                    detail: `#${el.id || el.className} text="${t}"`
                });
            }
        }

        return {
            scrollWidth: docW,
            innerWidth: winW,
            visible_buttons: visibleBtns.length,
            issues: issues
        };
    }""", [view_name, viewport_label])


def list_visible_buttons(page: Any) -> List[Dict[str, Any]]:
    return page.evaluate("""() => {
        const els = [...document.querySelectorAll('button, [role="tab"], [role="button"], .nav-item, .tab-btn, .tab, a.btn')];
        const out = [];
        els.forEach((el, idx) => {
            if (el.offsetParent === null) return;
            const r = el.getBoundingClientRect();
            if (r.width === 0 || r.height === 0) return;
            const text = (el.innerText || el.textContent || '').trim().replace(/\\s+/g, ' ').slice(0, 70);
            const attrs = {};
            for (const a of el.attributes) {
                if (a.name.startsWith('data-') || ['id', 'type', 'role', 'href', 'aria-label', 'title'].includes(a.name)) {
                    attrs[a.name] = a.value.slice(0, 60);
                }
            }
            const disabled = !!el.disabled || el.getAttribute('aria-disabled') === 'true';
            const isTab = el.hasAttribute('data-tab') || el.hasAttribute('data-view') || el.hasAttribute('data-section') || el.getAttribute('role') === 'tab' || el.classList.contains('tab-btn') || el.classList.contains('nav-item');
            const isActiveTab = isTab && (el.classList.contains('active') || el.getAttribute('aria-selected') === 'true');
            out.push({
                dom_idx: idx,
                tag: el.tagName,
                id: el.id || '',
                className: (el.className || '').toString().slice(0, 80),
                text: text,
                attrs: attrs,
                disabled: disabled,
                is_active_tab: isActiveTab,
                rect: {x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height)},
            });
        });
        return out;
    }""")


def find_nav_tabs(page: Any) -> List[Dict[str, Any]]:
    return page.evaluate("""() => {
        const sel = [
            '[data-view]',
            '[data-tab]',
            '[data-section]',
            '[data-page]',
            '[role="tab"]',
            '.nav-item',
            '.tab-btn',
            '.tab',
            '#meCardBtn',
        ].join(', ');
        const els = [...document.querySelectorAll(sel)];
        const out = [];
        const seen = new Set();
        els.forEach((el, i) => {
            if (el.offsetParent === null) return;
            const key = (el.id || '') + '|' + (el.getAttribute('data-view') || el.getAttribute('data-tab') || el.getAttribute('data-section') || (el.innerText || '').trim().slice(0, 40));
            if (seen.has(key)) return;
            seen.add(key);
            out.push({
                idx: i,
                id: el.id || '',
                data_view: el.getAttribute('data-view') || el.getAttribute('data-tab') || el.getAttribute('data-section') || '',
                text: (el.innerText || el.textContent || '').trim().replace(/\\s+/g, ' ').slice(0, 50),
                selector_hint: el.id ? '#' + el.id :
                    (el.getAttribute('data-view') ? `[data-view="${el.getAttribute('data-view')}"]` :
                    (el.getAttribute('data-tab') ? `[data-tab="${el.getAttribute('data-tab')}"]` : '')),
            });
        });
        return out;
    }""")


def run_create_new_account_counterfactual(browser: Any, url: str) -> Dict[str, Any]:
    """
    Counterfactual test for Create New Account (#newIdentityBtn):
    Verifies initial boot identity is valid, clicks #newIdentityBtn (plus any
    inline confirmation button if present), and proves localStorage identity
    genuinely rotated with zero errors and a non-empty vault key.
    """
    outcome: Dict[str, Any] = {
        "ran": False,
        "passed": True,
        "detail": "not_applicable",
        "errors": [],
    }
    ctx = browser.new_context(viewport={"width": 1440, "height": 900})
    ctx.add_init_script(INIT_HOOK_JS)
    page = ctx.new_page()

    pageerrors: List[str] = []
    console_errors: List[str] = []
    failed_reqs: List[str] = []

    page.on("pageerror", lambda e: pageerrors.append(str(e)))
    page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
    page.on("response", lambda r: failed_reqs.append(f"{r.status} {r.request.method} {r.url}") if r.status >= 400 else None)
    page.on("dialog", lambda d: d.accept())

    try:
        resp = page.goto(url, wait_until="networkidle", timeout=25000)
        if not resp or resp.status != 200:
            outcome["ran"] = True
            outcome["passed"] = False
            outcome["detail"] = f"HTTP {resp.status if resp else 'NONE'} on counterfactual boot"
            ctx.close()
            return outcome
        page.wait_for_timeout(1200)

        has_btn = page.evaluate("() => !!document.getElementById('newIdentityBtn')")
        if not has_btn:
            ctx.close()
            return outcome

        outcome["ran"] = True

        def read_identity_state() -> Dict[str, Any]:
            return page.evaluate("""() => {
                const raw = {};
                for (let i = 0; i < localStorage.length; i++) {
                    const k = localStorage.key(i);
                    raw[k] = localStorage.getItem(k) || '';
                }
                const pub = document.getElementById('vaultPubkeyId');
                const ecdh = document.getElementById('vaultEcdhFp');
                const handle = document.getElementById('vaultHandle');
                return {
                    ls_json: JSON.stringify(raw),
                    ls: raw,
                    pubkey_text: pub ? (pub.innerText || '').trim() : '',
                    ecdh_text: ecdh ? (ecdh.innerText || '').trim() : '',
                    handle_val: handle ? (handle.value || handle.innerText || '').trim() : '',
                };
            }""")

        before = read_identity_state()

        # Reveal #newIdentityBtn by navigating through tabs if hidden
        btn_loc = page.locator("#newIdentityBtn").first
        if not btn_loc.is_visible():
            for tab in find_nav_tabs(page):
                try:
                    if tab["selector_hint"]:
                        tloc = page.locator(tab["selector_hint"]).first
                    else:
                        tloc = page.locator('button, [role="tab"], .nav-item, .tab-btn, .tab').filter(has_text=tab["text"]).first
                    if tloc.is_visible():
                        tloc.click(timeout=2000)
                        page.wait_for_timeout(300)
                        if btn_loc.is_visible():
                            break
                except Exception:
                    continue

        if not btn_loc.is_visible():
            outcome["passed"] = False
            outcome["detail"] = "#newIdentityBtn exists in DOM but could not be revealed via navigation"
            ctx.close()
            return outcome

        before = read_identity_state()
        btn_loc.click(timeout=3000)
        page.wait_for_timeout(600)

        # If an inline confirmation modal/button appeared instead of window.confirm(), click it
        for confirm_sel in (
            "#confirmNewIdentityBtn",
            "#newIdentityConfirmBtn",
            "[data-confirm-new-account]",
            ".modal.open button.danger",
            ".modal.show button.danger",
            "[role='dialog'] button.danger",
            "[role='dialog'] button.btn-danger",
            "[role='dialog'] button.primary",
        ):
            cloc = page.locator(confirm_sel).first
            try:
                if cloc.count() > 0 and cloc.is_visible():
                    cloc.click(timeout=2000)
                    page.wait_for_timeout(800)
                    break
            except Exception:
                pass

        page.wait_for_timeout(800)
        after = read_identity_state()

        errors: List[str] = []
        if pageerrors:
            errors.append(f"pageerrors={pageerrors}")
        if console_errors:
            errors.append(f"console_errors={console_errors}")
        if failed_reqs:
            errors.append(f"failed_requests={failed_reqs}")
        if before["ls_json"] == after["ls_json"]:
            errors.append("counterfactual_failed: localStorage identity did not change after clicking #newIdentityBtn")

        # Validate no empty vault_key_b64 in any stored JSON identity
        for k, v in after["ls"].items():
            if "vault_key_b64" in v:
                try:
                    parsed = json.loads(v)
                    if isinstance(parsed, dict) and not parsed.get("vault_key_b64"):
                        errors.append(f"empty_vault_key_b64 in localStorage[{k!r}]")
                except Exception:
                    pass

        if after["pubkey_text"] in ("-", "undefined", "null"):
            errors.append(f"unhydrated #vaultPubkeyId={after['pubkey_text']!r}")
        if after["ecdh_text"] in ("-", "undefined", "null"):
            errors.append(f"unhydrated #vaultEcdhFp={after['ecdh_text']!r}")

        outcome["errors"] = errors
        outcome["passed"] = len(errors) == 0
        outcome["detail"] = "OK: identity rotated cleanly with 0 errors" if outcome["passed"] else "; ".join(errors)
    except Exception as exc:
        outcome["ran"] = True
        outcome["passed"] = False
        outcome["errors"].append(str(exc))
        outcome["detail"] = f"exception: {exc}"
    finally:
        ctx.close()
    return outcome


def audit_surface(browser: Any, base_url: str, path: str, run_account_cf: bool = True) -> Dict[str, Any]:
    url = base_url.rstrip("/") + path
    result: Dict[str, Any] = {
        "surface": path,
        "url": url,
        "http_status": None,
        "title": "",
        "boot_console_errors": [],
        "boot_console_warnings": [],
        "boot_pageerrors": [],
        "boot_failed_requests": [],
        "duplicate_js_functions": [],
        "js_dialog_jargon": [],
        "tabs": [],
        "buttons_tested": [],
        "dead_buttons": [],
        "error_buttons": [],
        "visible_jargon": [],
        "layout_issues_desktop": [],
        "layout_issues_mobile": [],
        "all_console_errors": [],
        "all_pageerrors": [],
        "all_failed_requests": [],
        "account_counterfactual": {"ran": False, "passed": True, "detail": "skipped", "errors": []},
    }

    ctx = browser.new_context(viewport={"width": 1440, "height": 900}, accept_downloads=True)
    ctx.add_init_script(INIT_HOOK_JS)
    page = ctx.new_page()

    console_errors: List[str] = []
    console_warnings: List[str] = []
    pageerrors: List[str] = []
    failed_requests: List[Dict[str, Any]] = []
    all_requests: List[Dict[str, Any]] = []
    dialogs: List[Dict[str, str]] = []
    downloads: List[str] = []

    def on_console(m: Any) -> None:
        if m.type == "error":
            console_errors.append(m.text)
        elif m.type == "warning":
            console_warnings.append(m.text)

    def on_pageerror(e: Any) -> None:
        stack = getattr(e, "stack", "") or ""
        first_lines = stack.splitlines()[0:3]
        pageerrors.append(f"{e} | {' / '.join(first_lines)}")

    def on_response(r: Any) -> None:
        entry = {"status": r.status, "method": r.request.method, "url": r.url}
        all_requests.append(entry)
        if r.status >= 400:
            failed_requests.append(entry)

    def on_requestfailed(req: Any) -> None:
        entry = {"status": "FAILED", "method": req.method, "url": req.url, "failure": req.failure}
        all_requests.append(entry)
        failed_requests.append(entry)

    def on_dialog(d: Any) -> None:
        dialogs.append({"type": d.type, "message": d.message})
        try:
            d.accept()
        except Exception:
            pass

    def on_download(dl: Any) -> None:
        downloads.append(dl.suggested_filename)

    page.on("console", on_console)
    page.on("pageerror", on_pageerror)
    page.on("response", on_response)
    page.on("requestfailed", on_requestfailed)
    page.on("dialog", on_dialog)
    page.on("download", on_download)

    try:
        resp = page.goto(url, wait_until="networkidle", timeout=25000)
        result["http_status"] = resp.status if resp else None
    except Exception:
        try:
            resp = page.goto(url, wait_until="domcontentloaded", timeout=20000)
            result["http_status"] = resp.status if resp else None
        except Exception as e2:
            result["boot_pageerrors"].append(f"Navigation failed: {e2}")
            result["all_pageerrors"] = list(result["boot_pageerrors"])
            ctx.close()
            return result

    page.wait_for_timeout(1200)
    result["title"] = page.title()
    result["boot_console_errors"] = list(console_errors)
    result["boot_console_warnings"] = list(console_warnings)
    result["boot_pageerrors"] = list(pageerrors)
    result["boot_failed_requests"] = list(failed_requests)

    raw_html = page.content()
    result["duplicate_js_functions"] = find_duplicate_js_functions(raw_html)
    result["js_dialog_jargon"] = scan_script_user_strings(raw_html)

    tabs = find_nav_tabs(page)
    result["tabs"] = tabs

    views_to_visit: List[Tuple[str, Optional[Dict[str, Any]]]] = [("initial", None)]
    for t in tabs:
        label = t["data_view"] or t["id"] or t["text"] or f"tab_{t['idx']}"
        views_to_visit.append((label, t))

    tested_btn_keys = set()
    seen_jargon_keys = set()

    for view_label, tab_info in views_to_visit:
        if tab_info is not None:
            try:
                if tab_info["selector_hint"]:
                    loc = page.locator(tab_info["selector_hint"]).first
                else:
                    loc = page.locator('button, [role="tab"], .nav-item, .tab-btn, .tab').filter(has_text=tab_info["text"]).first
                if loc.is_visible():
                    loc.click(timeout=3000)
                    page.wait_for_timeout(450)
            except Exception as e:
                result["error_buttons"].append({
                    "view": view_label,
                    "button": tab_info["text"] or tab_info["id"],
                    "status": "TAB_CLICK_ERROR",
                    "detail": str(e)[:150],
                })
                continue

        vis_text = page.evaluate("() => document.body ? document.body.innerText : ''")
        allow_dns_dkim = "dns" in view_label.lower()
        for hit in scan_jargon(vis_text, f"view:{view_label}", allow_dns_dkim=allow_dns_dkim):
            jk = (hit["category"], tuple(hit["samples"]))
            if jk not in seen_jargon_keys:
                seen_jargon_keys.add(jk)
                result["visible_jargon"].append(hit)

        lay = check_layout(page, view_label, "1440x900")
        result["layout_issues_desktop"].extend(lay["issues"])

        btns = list_visible_buttons(page)
        for b in btns:
            btn_key = (
                b["id"] or "",
                b["text"],
                b["attrs"].get("data-view", ""),
                b["attrs"].get("data-tab", ""),
                b["attrs"].get("data-algo", ""),
                b["attrs"].get("data-gtab", ""),
                b["attrs"].get("data-section", ""),
            )
            if btn_key in tested_btn_keys:
                continue
            if b.get("is_active_tab") and len(tabs) >= 2:
                # Defer testing already-active tab until we are on another tab so click genuinely switches views.
                continue
            tested_btn_keys.add(btn_key)

            if "data-delete-post" in b["attrs"]:
                result["buttons_tested"].append({
                    "view": view_label,
                    "id": b["id"],
                    "text": b["text"],
                    "status": "SKIPPED_SAFETY",
                    "detail": "Skipped delete-post on shared live data",
                })
                continue

            if b["disabled"]:
                result["buttons_tested"].append({
                    "view": view_label,
                    "id": b["id"],
                    "text": b["text"],
                    "status": "DISABLED",
                    "detail": "Button is disabled in current state",
                })
                continue

            # Dismiss any lingering modal overlay opened by a previous button in this view
            # so subsequent underlying buttons are not intercepted by its backdrop.
            try:
                has_open_modal = page.evaluate("""() => {
                    const m = document.querySelector('.modal-backdrop.open, .modal-backdrop.show, .modal.open, .modal.show, [role="dialog"][open]');
                    if (!m) return false;
                    const st = getComputedStyle(m);
                    return st.display !== 'none' && st.visibility !== 'hidden';
                }""")
                if has_open_modal:
                    page.keyboard.press("Escape")
                    page.wait_for_timeout(150)
                    still_open = page.evaluate("""() => {
                        const m = document.querySelector('.modal-backdrop.open, .modal-backdrop.show, .modal.open, .modal.show, [role="dialog"][open]');
                        if (!m) return false;
                        const st = getComputedStyle(m);
                        if (st.display === 'none' || st.visibility === 'hidden') return false;
                        const btn = m.querySelector('button[aria-label="Close"], .modal-close, button');
                        if (btn && /close|done|cancel/i.test((btn.innerText || btn.getAttribute('aria-label') || '').trim())) {
                            btn.click();
                            return true;
                        }
                        return true;
                    }""")
                    if still_open:
                        page.wait_for_timeout(150)
            except Exception:
                pass

            if tab_info is not None and tab_info["selector_hint"]:
                try:
                    tloc = page.locator(tab_info["selector_hint"]).first
                    if tloc.is_visible():
                        target_vis = page.evaluate("""([id, text]) => {
                            if (id) { const e = document.getElementById(id); return !!(e && e.offsetParent !== null); }
                            const els = [...document.querySelectorAll('button, [role="tab"], [role="button"], .nav-item, .tab-btn, .tab, a.btn')];
                            return els.some(e => e.offsetParent !== null && (e.innerText || e.textContent || '').trim().replace(/\\s+/g, ' ').slice(0, 70) === text);
                        }""", [b["id"], b["text"]])
                        if not target_vis:
                            tloc.click(timeout=2000)
                            page.wait_for_timeout(300)
                except Exception:
                    pass

            before = dom_snapshot(page)
            n_req0 = len(all_requests)
            n_fail0 = len(failed_requests)
            n_err0 = len(pageerrors)
            n_cerr0 = len(console_errors)
            n_dlg0 = len(dialogs)
            n_dl0 = len(downloads)

            click_err = None
            try:
                if b["id"]:
                    loc = page.locator(f"#{b['id']}").first
                elif b["attrs"].get("data-view"):
                    loc = page.locator(f'[data-view="{b["attrs"]["data-view"]}"]').first
                elif b["attrs"].get("data-tab"):
                    loc = page.locator(f'[data-tab="{b["attrs"]["data-tab"]}"]').first
                elif b["attrs"].get("data-algo"):
                    loc = page.locator(f'[data-algo="{b["attrs"]["data-algo"]}"]').first
                elif b["attrs"].get("data-gtab"):
                    loc = page.locator(f'[data-gtab="{b["attrs"]["data-gtab"]}"]').first
                else:
                    loc = page.locator('button, [role="tab"], [role="button"], .nav-item, .tab-btn, .tab, a.btn').filter(has_text=b["text"]).first
                if not loc.is_visible():
                    result["buttons_tested"].append({
                        "view": view_label,
                        "id": b["id"],
                        "text": b["text"],
                        "status": "NOT_VISIBLE",
                        "detail": "Became hidden before click",
                    })
                    continue
                loc.click(timeout=3000)
                page.wait_for_timeout(500)
            except Exception as e:
                click_err = str(e)[:180]

            after = dom_snapshot(page)
            new_reqs = all_requests[n_req0:]
            new_fails = failed_requests[n_fail0:]
            new_errs = pageerrors[n_err0:]
            new_cerrs = console_errors[n_cerr0:]
            new_dlgs = dialogs[n_dlg0:]
            new_dls = downloads[n_dl0:]
            new_hook_events = after["events"][before["events_count"]:]

            dom_changed = (
                hash_str(before["dom_sig"]) != hash_str(after["dom_sig"])
                or before["inputs"] != after["inputs"]
                or before["active"] != after["active"]
                or before["ls"] != after["ls"]
                or before["toast"] != after["toast"]
                or before["url"] != after["url"]
                or before["theme"] != after["theme"]
            )

            effects: List[str] = []
            if dom_changed:
                if before["toast"] != after["toast"] and after["toast"]:
                    effects.append(f"toast={after['toast']!r}")
                if before["theme"] != after["theme"]:
                    effects.append(f"theme={after['theme']!r}")
                if before["url"] != after["url"]:
                    effects.append("url_changed")
                if before["active"] != after["active"]:
                    effects.append("active_state_changed")
                if hash_str(before["dom_sig"]) != hash_str(after["dom_sig"]):
                    effects.append(f"text_delta={after['text_len'] - before['text_len']:+d}")
                if before["ls"] != after["ls"]:
                    effects.append("localStorage_changed")
            if new_reqs:
                effects.append(f"net={len(new_reqs)}({','.join(str(r['status']) for r in new_reqs[:4])})")
            if new_dlgs:
                effects.append(f"dialogs={[d['type'] + ':' + d['message'][:50] for d in new_dlgs]}")
            if new_dls:
                effects.append(f"downloads={new_dls}")
            if new_hook_events:
                effects.append(f"hooks={[ev['type'] for ev in new_hook_events[:4]]}")

            status = "OK"
            if click_err or new_errs or new_cerrs or new_fails:
                status = "ERROR"
            elif not dom_changed and not new_reqs and not new_dlgs and not new_dls and not new_hook_events:
                status = "DEAD"

            rec = {
                "view": view_label,
                "id": b["id"],
                "text": b["text"],
                "status": status,
                "effects": effects,
                "pageerrors": new_errs,
                "console_errors": new_cerrs,
                "failed_requests": new_fails,
                "dialogs": new_dlgs,
                "click_error": click_err,
            }
            result["buttons_tested"].append(rec)
            if status == "DEAD":
                result["dead_buttons"].append(rec)
            elif status == "ERROR":
                result["error_buttons"].append(rec)

    # Mobile viewport check (390x844) across fresh initial screen and every tab
    page.set_viewport_size({"width": 390, "height": 844})
    try:
        page.goto(url, wait_until="networkidle", timeout=20000)
        page.wait_for_timeout(700)
        mlay0 = check_layout(page, "initial_mobile", "390x844")
        result["layout_issues_mobile"].extend(mlay0["issues"])
        for t in find_nav_tabs(page):
            tlabel = t["data_view"] or t["id"] or t["text"] or f"tab_{t['idx']}"
            try:
                if t["selector_hint"]:
                    tloc = page.locator(t["selector_hint"]).first
                else:
                    tloc = page.locator('button, [role="tab"], .nav-item, .tab-btn, .tab').filter(has_text=t["text"]).first
                if tloc.is_visible():
                    tloc.click(timeout=2000)
                    page.wait_for_timeout(350)
                    mlay_t = check_layout(page, f"mobile:{tlabel}", "390x844")
                    result["layout_issues_mobile"].extend(mlay_t["issues"])
            except Exception:
                continue
    except Exception as exc:
        pageerrors.append(f"mobile_check_failed: {exc}")

    result["all_console_errors"] = console_errors
    result["all_pageerrors"] = pageerrors
    result["all_failed_requests"] = failed_requests
    ctx.close()

    if run_account_cf:
        cf = run_create_new_account_counterfactual(browser, url)
        result["account_counterfactual"] = cf

    return result


def evaluate_failures(surface_report: Dict[str, Any], strict_jargon: bool = False) -> List[str]:
    failures: List[str] = []
    if surface_report["http_status"] != 200:
        failures.append(f"http_status={surface_report['http_status']}")
    if surface_report["all_pageerrors"]:
        failures.append(f"pageerrors={len(surface_report['all_pageerrors'])}")
    if surface_report["all_console_errors"]:
        failures.append(f"console_errors={len(surface_report['all_console_errors'])}")
    if surface_report["all_failed_requests"]:
        failures.append(f"failed_requests={len(surface_report['all_failed_requests'])}")
    if surface_report["duplicate_js_functions"]:
        failures.append(f"duplicate_js_functions={len(surface_report['duplicate_js_functions'])}")
    if surface_report["dead_buttons"]:
        failures.append(f"dead_buttons={len(surface_report['dead_buttons'])}")
    if surface_report["error_buttons"]:
        failures.append(f"error_buttons={len(surface_report['error_buttons'])}")
    if surface_report["layout_issues_desktop"]:
        failures.append(f"desktop_layout_issues={len(surface_report['layout_issues_desktop'])}")
    if surface_report["layout_issues_mobile"]:
        failures.append(f"mobile_layout_issues={len(surface_report['layout_issues_mobile'])}")
    cf = surface_report.get("account_counterfactual") or {}
    if cf.get("ran") and not cf.get("passed"):
        failures.append(f"account_counterfactual_failed({cf.get('detail', '')})")
    if strict_jargon and (surface_report["visible_jargon"] or surface_report["js_dialog_jargon"]):
        failures.append(
            f"residual_jargon={len(surface_report['visible_jargon'])}+{len(surface_report['js_dialog_jargon'])}"
        )
    return failures


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Blind Labs Permanent UI Contract Self-Test Harness")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Target base URL (e.g. http://127.0.0.1:8093)")
    parser.add_argument(
        "--surfaces",
        nargs="+",
        default=["social,sign,mail,finance"],
        help="Comma- or space-separated surface names (social,sign,mail,finance) or URL paths (e.g. /)",
    )
    parser.add_argument("--json-out", default="", help="Optional path to write full JSON audit report")
    parser.add_argument("--chrome", default="", help="Optional explicit path to Chrome/Chromium executable")
    parser.add_argument("--strict-jargon", action="store_true", help="Fail exit code on residual visible/dialog jargon")
    parser.add_argument(
        "--skip-account-counterfactual",
        action="store_true",
        help="Skip Create New Account (#newIdentityBtn) counterfactual test",
    )
    args = parser.parse_args(argv)

    surfaces = parse_surfaces(args.surfaces)
    chrome = find_chrome(args.chrome or None)
    if not chrome:
        print("ERROR: No Chromium/Chrome binary found. Pass --chrome or set CHROME_BIN.", file=sys.stderr)
        return 2

    print(f"[ui-self-test] Browser: {chrome}")
    print(f"[ui-self-test] Target:  {args.base_url} surfaces={surfaces}")

    report: Dict[str, Any] = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "browser": chrome,
        "base_url": args.base_url,
        "surfaces": [],
        "passed": True,
    }

    total_failures = 0
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("ERROR: playwright Python package is required. Install playwright or run via Playwright Python.", file=sys.stderr)
        return 2

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, executable_path=chrome)
        for s in surfaces:
            t0 = time.time()
            print(f"\n>>> Auditing {s} ...", flush=True)
            res = audit_surface(browser, args.base_url, s, run_account_cf=not args.skip_account_counterfactual)
            res["elapsed_sec"] = round(time.time() - t0, 2)
            failures = evaluate_failures(res, strict_jargon=args.strict_jargon)
            res["failures"] = failures
            res["passed"] = len(failures) == 0
            if not res["passed"]:
                total_failures += 1
            report["surfaces"].append(res)
            status_tag = "PASS" if res["passed"] else "FAIL"
            cf = res["account_counterfactual"]
            cf_str = "n/a" if not cf["ran"] else ("PASS" if cf["passed"] else "FAIL")
            print(
                f"<<< [{status_tag}] {s}: HTTP {res['http_status']} | tabs={len(res['tabs'])} | "
                f"btns={len(res['buttons_tested'])} | DEAD={len(res['dead_buttons'])} | "
                f"ERR_BTNS={len(res['error_buttons'])} | pageerr={len(res['all_pageerrors'])} | "
                f"cerr={len(res['all_console_errors'])} | http>=400={len(res['all_failed_requests'])} | "
                f"dup_fns={len(res['duplicate_js_functions'])} | "
                f"layout(D/M)={len(res['layout_issues_desktop'])}/{len(res['layout_issues_mobile'])} | "
                f"jargon={len(res['visible_jargon'])}+{len(res['js_dialog_jargon'])} | "
                f"acct_cf={cf_str} | {res['elapsed_sec']}s",
                flush=True,
            )
        browser.close()

    report["passed"] = total_failures == 0
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"\n[ui-self-test] JSON report written to {args.json_out}")

    print("\n================ UI CONTRACT SUMMARY ================")
    for r in report["surfaces"]:
        tag = "PASS" if r["passed"] else "FAIL"
        print(f"\n## [{tag}] {r['surface']} ({r['title']}) [HTTP {r['http_status']}]")
        if r["failures"]:
            print("  [FAILURES]:", ", ".join(r["failures"]))
        if r["duplicate_js_functions"]:
            print("  [CRITICAL] Duplicate JS functions:", r["duplicate_js_functions"])
        if r["all_pageerrors"]:
            print("  [PAGEERRORS]:", r["all_pageerrors"])
        if r["all_console_errors"]:
            print("  [CONSOLE ERRORS]:", r["all_console_errors"])
        if r["all_failed_requests"]:
            print("  [HTTP>=400]:", r["all_failed_requests"])
        if r["error_buttons"]:
            for b in r["error_buttons"]:
                print(f"  [ERROR BTN] [{b['view']}] #{b.get('id', '')} '{b.get('text', b.get('button', ''))}': {b.get('click_error') or b.get('failed_requests') or b.get('console_errors')}")
        if r["dead_buttons"]:
            for b in r["dead_buttons"]:
                print(f"  [DEAD BTN] [{b['view']}] #{b['id']} '{b['text']}'")
        if r["layout_issues_desktop"]:
            for li in r["layout_issues_desktop"]:
                print(f"  [LAYOUT 1440x900] [{li['view']}] {li['type']}: {li['detail']}")
        if r["layout_issues_mobile"]:
            for li in r["layout_issues_mobile"]:
                print(f"  [LAYOUT 390x844] [{li['view']}] {li['type']}: {li['detail']}")
        if r["visible_jargon"]:
            for j in r["visible_jargon"]:
                print(f"  [JARGON] ({j['source']}) {j['category']} x{j['count']}: {j['samples']}")
        if r["js_dialog_jargon"]:
            for j in r["js_dialog_jargon"]:
                print(f"  [DIALOG JARGON] {j['category']} x{j['count']}: {j['samples']}")
        cf = r["account_counterfactual"]
        if cf["ran"]:
            print(f"  [ACCOUNT COUNTERFACTUAL]: {'PASS' if cf['passed'] else 'FAIL'} - {cf['detail']}")

    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
