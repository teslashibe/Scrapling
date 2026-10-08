"""Find CAPTCHA widgets in a page and inject solved tokens, for use by anti-bot handlers.

Typical flow inside a handler::

    await install_capture(context)          # once, before navigation (records turnstile/grecaptcha/hcaptcha render calls)
    ...
    widgets = await find_widgets(page)      # sitekeys, actions, cData, chlPageData, enterprise flags, ...
    request = token_request(widgets[0], page.url)
    token = await solver.solve_token(**request, deadline=deadline)
    await inject_token(page, token)         # fills the response fields and calls the page's own callbacks

Why the capture script matters: many integrations render widgets with ``turnstile.render(el, {callback})`` /
``grecaptcha.render(el, {callback})`` and only proceed when that callback fires. Filling the hidden
``cf-turnstile-response`` / ``g-recaptcha-response`` field alone does nothing for them. 2Captcha documents the same
technique for Turnstile challenge pages (https://2captcha.com/api-docs/cloudflare-turnstile): intercept
``turnstile.render``, keep ``cData``/``chlPageData``/``action`` and the callback, then call the callback with the token.

All page JavaScript runs in the page's main world (Patchright evaluates in an isolated world by default, where the
vendor globals are invisible). Nothing here moves the OS mouse, focuses windows or navigates.
"""

from __future__ import annotations

import json
import re
import secrets
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlsplit

from .base import Token

__all__ = [
    "DEFAULT_NAMESPACE",
    "capture_script",
    "install_capture",
    "evaluate_main_world",
    "read_captured",
    "find_widgets",
    "token_request",
    "inject_turnstile",
    "inject_recaptcha",
    "inject_hcaptcha",
    "inject_token",
    "set_aws_waf_cookie",
]

#: A per-process property name for the capture state, so pages cannot look for a fixed marker.
DEFAULT_NAMESPACE = "__" + secrets.token_hex(5)

_CAPTURE_JS = r"""
(() => {
  const NS = __NS__;
  try {
    if (Object.prototype.hasOwnProperty.call(window, NS)) return;
    // Never touch the vendors' own iframes; only the pages that host their widgets.
    if (window.top !== window && /(^|\.)(cloudflare\.com|google\.com|recaptcha\.net|gstatic\.com|hcaptcha\.com|arkoselabs\.com)$/.test(location.hostname)) return;
    const state = { turnstile: [], recaptcha: [], hcaptcha: [], cbs: [] };
    Object.defineProperty(window, NS, { value: state, enumerable: false, configurable: false, writable: false });
    const wrapped = new WeakSet();
    const remember = (cb) => {
      if (typeof cb === 'function') { state.cbs.push(cb); return state.cbs.length - 1; }
      if (typeof cb === 'string' && cb) return cb;
      return null;
    };
    const elementOf = (el) => {
      try { return typeof el === 'string' ? (document.getElementById(el) || document.querySelector(el)) : el; } catch (e) { return null; }
    };
    const attrOf = (el, name) => { try { return el && el.getAttribute ? el.getAttribute(name) : null; } catch (e) { return null; } };
    const record = (vendor, target, opts, extra) => {
      const o = (opts && typeof opts === 'object') ? opts : {};
      const el = elementOf(target);
      state[vendor].push(Object.assign({
        sitekey: o.sitekey || attrOf(el, 'data-sitekey') || null,
        action: o.action || attrOf(el, 'data-action') || null,
        callback: remember(o.callback || attrOf(el, 'data-callback')),
      }, extra(o, el)));
    };
    const proxyOf = (fn, onCall) => {
      if (typeof fn !== 'function' || wrapped.has(fn)) return fn;
      const p = new Proxy(fn, { apply(t, self, args) { try { onCall(args); } catch (e) {} return Reflect.apply(t, self, args); } });
      wrapped.add(p);
      return p;
    };
    // Wrap owner[prop] now, and wrap whatever gets assigned to it later.
    const hookFn = (owner, prop, onCall) => {
      try {
        const d = Object.getOwnPropertyDescriptor(owner, prop);
        if (d && d.get) { const cur = owner[prop]; const p = proxyOf(cur, onCall); if (p !== cur) owner[prop] = p; return; }
        if (d && !d.configurable) { if (d.writable) owner[prop] = proxyOf(owner[prop], onCall); return; }
        let value = proxyOf(d ? d.value : undefined, onCall);
        Object.defineProperty(owner, prop, { configurable: true, enumerable: true,
          get() { return value; }, set(v) { value = proxyOf(v, onCall); } });
      } catch (e) {}
    };
    // Run hook(value) whenever owner[prop] is assigned (vendor libraries assign their globals once loaded).
    const trapProp = (owner, prop, hook) => {
      try {
        const d = Object.getOwnPropertyDescriptor(owner, prop);
        if (d && (!d.configurable || d.get)) return;
        let value = d ? d.value : undefined;
        Object.defineProperty(owner, prop, { configurable: true, enumerable: true,
          get() { return value; }, set(v) { value = v; try { hook(v); } catch (e) {} } });
      } catch (e) {}
    };
    const hooked = new WeakSet();
    const hookTurnstile = (t) => {
      if (!t || hooked.has(t)) return; hooked.add(t);
      hookFn(t, 'render', (a) => record('turnstile', a[0], a[1], (o) => ({
        cdata: o.cData || null, page_data: o.chlPageData || null, response_field_name: o['response-field-name'] || null })));
    };
    const hookRecaptcha = (g, enterprise) => {
      // hCaptcha's api.js aliases window.grecaptcha to itself (reCAPTCHA compatibility mode).
      if (!g || hooked.has(g) || g === window.hcaptcha) return; hooked.add(g);
      hookFn(g, 'render', (a) => record('recaptcha', a[0], a[1], (o, el) => ({
        version: 'v2', enterprise: !!enterprise, invisible: (o.size || attrOf(el, 'data-size')) === 'invisible', data_s: o.s || null })));
      hookFn(g, 'execute', (a) => {
        if (typeof a[0] === 'string' && a[0].length >= 20) {
          state.recaptcha.push({ sitekey: a[0], action: (a[1] && a[1].action) || null, version: 'v3', enterprise: !!enterprise, callback: null });
        }
      });
      if (!enterprise) {
        if (g.enterprise) hookRecaptcha(g.enterprise, true);
        else trapProp(g, 'enterprise', (v) => hookRecaptcha(v, true));
      }
    };
    const hookHcaptcha = (h) => {
      if (!h || hooked.has(h)) return; hooked.add(h);
      hookFn(h, 'render', (a) => record('hcaptcha', a[0], a[1], (o, el) => ({
        invisible: (o.size || attrOf(el, 'data-size')) === 'invisible', data: o.rqdata || null })));
    };
    const scan = () => {
      try { hookTurnstile(window.turnstile); hookHcaptcha(window.hcaptcha); hookRecaptcha(window.grecaptcha, false);
            if (window.grecaptcha && window.grecaptcha.enterprise) hookRecaptcha(window.grecaptcha.enterprise, true); } catch (e) {}
    };
    // The vendor globals are deliberately not trapped on window: Turnstile's loader does nothing when a "turnstile"
    // property already exists (verified against the live api.js), and pages may test `'grecaptcha' in window`.
    // Instead, every vendor loader calls the page's ?onload= callback right after defining its global, so wrap that
    // callback: the render() hook is then in place before the page's own code calls render(). A MutationObserver
    // and a short poll cover pages that render later or without an onload parameter.
    const VENDOR_SCRIPT = /(turnstile\/v0\/api\.js|\/recaptcha\/(api|enterprise)\.js|hcaptcha\.com\/1\/api\.js)/;
    const seenScripts = new WeakSet();
    const onScript = (el) => {
      try {
        if (!el || el.tagName !== 'SCRIPT' || seenScripts.has(el)) return;
        seenScripts.add(el);
        const src = el.src || '';
        if (!VENDOR_SCRIPT.test(src)) return;
        const m = /[?&]onload=([^&#]+)/.exec(src);
        if (m) hookFn(window, decodeURIComponent(m[1]), () => scan());
      } catch (e) {}
    };
    try {
      new MutationObserver((records) => {
        for (const r of records) for (const n of r.addedNodes) onScript(n);
        scan();
      }).observe(document, { childList: true, subtree: true });
    } catch (e) {}
    let ticks = 0;
    const timer = setInterval(() => { scan(); if (++ticks > 600) clearInterval(timer); }, 50);
  } catch (e) {}
})();
"""

_READ_JS = r"""
(ns) => {
  const st = window[ns];
  if (!st) return null;
  const clean = (e) => Object.assign({}, e, { callback: e.callback === null || e.callback === undefined ? null : (typeof e.callback === 'number' ? 'function' : String(e.callback)) });
  return { turnstile: st.turnstile.map(clean), recaptcha: st.recaptcha.map(clean), hcaptcha: st.hcaptcha.map(clean) };
}
"""

_DOM_JS = r"""
() => {
  const out = [];
  const a = (el, n) => el.getAttribute(n) || null;
  document.querySelectorAll('.cf-turnstile[data-sitekey], div[data-sitekey^="0x"]').forEach((el) => out.push({
    vendor: 'turnstile', sitekey: a(el, 'data-sitekey'), action: a(el, 'data-action'), cdata: a(el, 'data-cdata'),
    callback: a(el, 'data-callback'), source: 'dom' }));
  let enterpriseScript = false;
  document.querySelectorAll('script[src]').forEach((s) => {
    const m = s.src.match(/\/recaptcha\/(api|enterprise)\.js(?:\?(.*))?$/);
    if (!m) return;
    if (m[1] === 'enterprise') enterpriseScript = true;
    const r = new URLSearchParams(m[2] || '').get('render');
    if (r && r !== 'explicit' && r !== 'onload') out.push({ vendor: 'recaptcha', version: 'v3', sitekey: r, enterprise: m[1] === 'enterprise', source: 'script',
      api_domain: s.src.includes('recaptcha.net') ? 'recaptcha.net' : null });
  });
  document.querySelectorAll('.g-recaptcha[data-sitekey]').forEach((el) => out.push({
    vendor: 'recaptcha', version: 'v2', sitekey: a(el, 'data-sitekey'), action: a(el, 'data-action'),
    invisible: a(el, 'data-size') === 'invisible', data_s: a(el, 'data-s'), enterprise: enterpriseScript, callback: a(el, 'data-callback'), source: 'dom' }));
  document.querySelectorAll('.h-captcha[data-sitekey]').forEach((el) => out.push({
    vendor: 'hcaptcha', sitekey: a(el, 'data-sitekey'), invisible: a(el, 'data-size') === 'invisible', callback: a(el, 'data-callback'), source: 'dom' }));
  return out;
}
"""

_INJECT_JS = r"""
({ ns, vendor, token, sitekey }) => {
  const st = window[ns];
  const mine = (key) => !sitekey || !key || key === sitekey;
  const res = { fields: 0, callbacks: 0, errors: [] };
  const called = new Set();
  const call = (cb) => {
    let fn = cb;
    if (typeof cb === 'number' && st) fn = st.cbs[cb];
    else if (typeof cb === 'string') fn = cb.split('.').reduce((o, k) => (o == null ? undefined : o[k]), window);
    if (typeof fn !== 'function' || called.has(fn)) return;
    called.add(fn);
    try { fn(token); res.callbacks++; } catch (e) { res.errors.push(String(e && e.message || e).slice(0, 200)); }
  };
  const fill = (selector) => document.querySelectorAll(selector).forEach((el) => {
    try {
      el.value = token;
      if (el.tagName === 'TEXTAREA') el.innerHTML = token;
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
      res.fields++;
    } catch (e) { res.errors.push(String(e).slice(0, 200)); }
  });
  const getResponse = (obj) => { try { if (obj && typeof obj.getResponse === 'function') obj.getResponse = function () { return token; }; } catch (e) {} };
  if (vendor === 'turnstile') {
    const names = new Set(['cf-turnstile-response']);
    if (st) st.turnstile.forEach((w) => { if (w.response_field_name && mine(w.sitekey)) names.add(w.response_field_name); });
    names.forEach((n) => fill(`input[name="${CSS.escape(n)}"], textarea[name="${CSS.escape(n)}"]`));
    fill('.cf-turnstile textarea[name="g-recaptcha-response"]');
    getResponse(window.turnstile);
    if (st) st.turnstile.forEach((w) => { if (mine(w.sitekey)) call(w.callback); });
    document.querySelectorAll('.cf-turnstile[data-callback], div[data-sitekey^="0x"][data-callback]').forEach((el) => {
      if (mine(el.getAttribute('data-sitekey'))) call(el.getAttribute('data-callback'));
    });
  } else if (vendor === 'recaptcha') {
    fill('textarea[name="g-recaptcha-response"], textarea[id^="g-recaptcha-response"], input[name="g-recaptcha-response"]');
    const g = window.grecaptcha;
    getResponse(g);
    if (g && g.enterprise) getResponse(g.enterprise);
    const resolveExec = (obj) => { try { if (obj && typeof obj.execute === 'function') obj.execute = function () { return Promise.resolve(token); }; } catch (e) {} };
    resolveExec(g);
    if (g && g.enterprise) resolveExec(g.enterprise);
    if (st) st.recaptcha.forEach((w) => { if (mine(w.sitekey)) call(w.callback); });
    document.querySelectorAll('.g-recaptcha[data-callback]').forEach((el) => {
      if (mine(el.getAttribute('data-sitekey'))) call(el.getAttribute('data-callback'));
    });
    // Widgets rendered implicitly keep their callback inside ___grecaptcha_cfg.clients.
    try {
      const clients = (window.___grecaptcha_cfg || {}).clients || {};
      const seen = new Set();
      const walk = (obj, depth) => {
        if (!obj || typeof obj !== 'object' || depth > 4 || seen.has(obj)) return;
        seen.add(obj);
        if (typeof obj.sitekey === 'string' && !mine(obj.sitekey)) return;
        for (const key of Object.keys(obj)) {
          let v; try { v = obj[key]; } catch (e) { continue; }
          if (key === 'callback' && (typeof v === 'function' || typeof v === 'string')) call(v);
          else if (v && typeof v === 'object' && !(v instanceof Node)) walk(v, depth + 1);
        }
      };
      Object.keys(clients).forEach((id) => walk(clients[id], 0));
    } catch (e) { res.errors.push(String(e).slice(0, 200)); }
  } else if (vendor === 'hcaptcha') {
    fill('textarea[name="h-captcha-response"], textarea[name="g-recaptcha-response"]');
    document.querySelectorAll('iframe[data-hcaptcha-response]').forEach((f) => { try { f.setAttribute('data-hcaptcha-response', token); res.fields++; } catch (e) {} });
    getResponse(window.hcaptcha);
    if (st) st.hcaptcha.forEach((w) => { if (mine(w.sitekey)) call(w.callback); });
    document.querySelectorAll('.h-captcha[data-callback]').forEach((el) => {
      if (mine(el.getAttribute('data-sitekey'))) call(el.getAttribute('data-callback'));
    });
  }
  return res;
}
"""


def capture_script(ns: str = DEFAULT_NAMESPACE) -> str:
    """Return the init script that records ``turnstile.render`` / ``grecaptcha.render|execute`` / ``hcaptcha.render``."""
    return _CAPTURE_JS.replace("__NS__", json.dumps(ns))


async def install_capture(target: Any, ns: str = DEFAULT_NAMESPACE) -> None:
    """Install :func:`capture_script` on a Page or BrowserContext. Must run before the page's scripts load."""
    await target.add_init_script(script=capture_script(ns))


async def evaluate_main_world(target: Any, expression: str, arg: Any = None) -> Any:
    """Evaluate in the page's main world (Patchright defaults to an isolated world; Playwright has no such option)."""
    try:
        return await target.evaluate(expression, arg, isolated_context=False)
    except TypeError:
        return await target.evaluate(expression, arg)


async def read_captured(target: Any, ns: str = DEFAULT_NAMESPACE) -> Optional[Dict[str, List[Dict[str, Any]]]]:
    """Return what the capture script recorded, or None when it is not installed in this frame."""
    return await evaluate_main_world(target, _READ_JS, ns)


async def find_widgets(page: Any, ns: str = DEFAULT_NAMESPACE, *, frame: Any = None) -> List[Dict[str, Any]]:
    """Discover Turnstile, reCAPTCHA, hCaptcha and FunCaptcha widgets on the page.

    Combines three sources: the capture script's records (most complete: includes ``cdata``/``page_data`` and
    whether a callback exists), the DOM (``data-sitekey`` containers and ``recaptcha/api.js?render=`` scripts) and
    the URLs of the vendors' own iframes (which also works for widgets inside closed shadow roots).
    Each item has ``vendor`` plus whatever is known of ``sitekey``, ``action``, ``cdata``, ``page_data``,
    ``version``, ``enterprise``, ``invisible``, ``data_s``, ``api_domain``, ``callback`` and ``source``.
    """
    target = frame or page
    found: List[Dict[str, Any]] = []
    try:
        captured = await read_captured(target, ns)
    except Exception:
        captured = None
    for vendor in ("turnstile", "recaptcha", "hcaptcha"):
        for item in (captured or {}).get(vendor, []):
            found.append(dict(item, vendor=vendor, source="render"))
    try:
        found.extend(await evaluate_main_world(target, _DOM_JS) or [])
    except Exception:
        pass
    frames = getattr(page, "frames", None) or []
    for f in frames:
        try:
            info = _parse_frame_url(f.url)
        except Exception:
            info = None
        if info:
            found.append(info)
    return _merge(found)


# Production keys start with "0x4"; Cloudflare's test keys start with "1x", "2x" or "3x".
_TURNSTILE_KEY = re.compile(r"^[0-3]x[0-9A-Za-z_-]{10,}$")


def _parse_frame_url(url: str) -> Optional[Dict[str, Any]]:
    parts = urlsplit(url or "")
    host = (parts.hostname or "").lower()
    path = parts.path
    if host == "challenges.cloudflare.com" and "/turnstile/" in path:
        key = next((seg for seg in path.split("/") if _TURNSTILE_KEY.match(seg)), None)
        if key:
            return {"vendor": "turnstile", "sitekey": key, "source": "frame"}
    if ("/recaptcha/api2/anchor" in path or "/recaptcha/enterprise/anchor" in path) and (
        host.endswith("google.com") or host.endswith("recaptcha.net")
    ):
        q = parse_qs(parts.query)
        key = _first(q, "k")
        if key:
            return {
                "vendor": "recaptcha",
                "version": "v2",
                "sitekey": key,
                "enterprise": "/enterprise/" in path,
                "invisible": _first(q, "size") == "invisible",
                "data_s": _first(q, "s"),
                "api_domain": "recaptcha.net" if host.endswith("recaptcha.net") else None,
                "source": "frame",
            }
    if host.endswith("hcaptcha.com") and "/captcha/" in path:
        q = parse_qs(parts.fragment)
        key = _first(q, "sitekey")
        if key:
            return {
                "vendor": "hcaptcha",
                "sitekey": key,
                "invisible": _first(q, "size") == "invisible",
                "source": "frame",
            }
    if host.endswith("arkoselabs.com") or host.endswith("funcaptcha.com"):
        q = parse_qs(parts.query)
        key = _first(q, "pk")
        if not key:
            key = next((seg for seg in path.split("/") if len(seg) == 36 and seg.count("-") == 4), None)
        if key:
            return {"vendor": "funcaptcha", "sitekey": key, "funcaptcha_subdomain": host, "source": "frame"}
    return None


def _first(query: Dict[str, List[str]], name: str) -> Optional[str]:
    values = query.get(name)
    return values[0] if values else None


def _merge(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge records describing the same widget (same vendor, sitekey and version), preferring richer sources."""
    order = {"render": 0, "dom": 1, "script": 2, "frame": 3}
    merged: Dict[tuple, Dict[str, Any]] = {}
    for item in sorted(items, key=lambda i: order.get(i.get("source", ""), 9)):
        if not item.get("sitekey"):
            continue
        key = (item["vendor"], item["sitekey"], item.get("version"))
        current = merged.get(key)
        if current is None:
            merged[key] = {k: v for k, v in item.items() if v is not None}
            continue
        for k, v in item.items():
            if v is not None and current.get(k) in (None, False, ""):
                current[k] = v
    # A v2 record from the iframe and the same key seen as v3 elsewhere are different widgets; keep both.
    return list(merged.values())


def token_request(widget: Dict[str, Any], page_url: str) -> Dict[str, Any]:
    """Turn a :func:`find_widgets` item into keyword arguments for ``solve_token``.

    A Turnstile widget that carries ``page_data`` (``chlPageData``) is a Cloudflare challenge page and maps to the
    experimental ``turnstile_challenge`` kind; a router refuses it unless ``experimental=True``.
    """
    vendor = widget.get("vendor")
    req: Dict[str, Any] = {"sitekey": widget.get("sitekey") or "", "page_url": page_url}

    def opt(name: str, key: Optional[str] = None) -> None:
        value = widget.get(key or name)
        if value not in (None, "", False):
            req[name] = value

    if vendor == "turnstile":
        req["kind"] = "turnstile_challenge" if widget.get("page_data") else "turnstile"
        opt("action")
        opt("cdata")
        opt("page_data")
    elif vendor == "recaptcha":
        enterprise = bool(widget.get("enterprise"))
        if widget.get("version") == "v3":
            req["kind"] = "recaptcha_v3_enterprise" if enterprise else "recaptcha_v3"
            opt("action")
        else:
            req["kind"] = "recaptcha_v2_enterprise" if enterprise else "recaptcha_v2"
            opt("invisible")
            opt("data_s")
            if enterprise and widget.get("data_s"):
                req["enterprise_payload"] = {"s": widget["data_s"]}
                req.pop("data_s", None)
            if enterprise:
                opt("action")
        opt("api_domain")
    elif vendor == "hcaptcha":
        req["kind"] = "hcaptcha"
        opt("invisible")
        opt("data")
    elif vendor == "funcaptcha":
        req["kind"] = "funcaptcha"
        opt("funcaptcha_subdomain")
    else:
        raise ValueError(f"unknown widget vendor {vendor!r}")
    return req


async def _inject(target: Any, vendor: str, token: str, ns: str, sitekey: Optional[str]) -> Dict[str, Any]:
    payload = {"ns": ns, "vendor": vendor, "token": str(token), "sitekey": sitekey or None}
    return await evaluate_main_world(target, _INJECT_JS, payload)


async def inject_turnstile(
    target: Any, token: str, *, sitekey: Optional[str] = None, ns: str = DEFAULT_NAMESPACE
) -> Dict[str, Any]:
    """Fill ``cf-turnstile-response`` fields, patch ``turnstile.getResponse`` and call the widgets' callbacks.

    With ``sitekey``, only callbacks of widgets rendered with that key are called (fields are always filled).
    Returns ``{"fields": n, "callbacks": n, "errors": [...]}``. The caller must still wait for the page to react.
    """
    return await _inject(target, "turnstile", token, ns, sitekey)


async def inject_recaptcha(
    target: Any, token: str, *, sitekey: Optional[str] = None, ns: str = DEFAULT_NAMESPACE
) -> Dict[str, Any]:
    """Fill ``g-recaptcha-response``, patch ``getResponse``/``execute`` (v2, v3, Enterprise) and call callbacks."""
    return await _inject(target, "recaptcha", token, ns, sitekey)


async def inject_hcaptcha(
    target: Any, token: str, *, sitekey: Optional[str] = None, ns: str = DEFAULT_NAMESPACE
) -> Dict[str, Any]:
    """Fill ``h-captcha-response``/``g-recaptcha-response``, patch ``hcaptcha.getResponse`` and call callbacks."""
    return await _inject(target, "hcaptcha", token, ns, sitekey)


_VENDOR_BY_KIND = {
    "turnstile": "turnstile",
    "turnstile_challenge": "turnstile",
    "recaptcha_v2": "recaptcha",
    "recaptcha_v2_enterprise": "recaptcha",
    "recaptcha_v3": "recaptcha",
    "recaptcha_v3_enterprise": "recaptcha",
    "hcaptcha": "hcaptcha",
}


async def inject_token(
    target: Any,
    token: str,
    *,
    kind: Optional[str] = None,
    sitekey: Optional[str] = None,
    ns: str = DEFAULT_NAMESPACE,
) -> Dict[str, Any]:
    """Inject a token for any widget kind. ``kind`` defaults to ``token.kind`` when given a :class:`~.base.Token`."""
    kind = kind or (token.kind if isinstance(token, Token) else None)
    vendor = _VENDOR_BY_KIND.get(kind or "")
    if vendor is None:
        raise ValueError(f"no injector for kind {kind!r}")
    return await _inject(target, vendor, token, ns, sitekey)


async def set_aws_waf_cookie(page: Any, token: str, url: str) -> None:
    """Store an ``aws-waf-token`` cookie for ``url``'s host in the page's browser context (reload afterwards)."""
    await page.context.add_cookies([{"name": "aws-waf-token", "value": str(token), "url": url}])
