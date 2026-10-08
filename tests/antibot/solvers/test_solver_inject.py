"""Widget discovery and token injection.

The browser tests serve local pages with stand-ins for the Turnstile, reCAPTCHA and hCaptcha client libraries that
behave like the real ones where it matters (globals assigned when the script loads, render() called from an onload
callback in the same task, reCAPTCHA's two-stage load and ``___grecaptcha_cfg.clients`` callbacks). They run a
headless browser with the sandbox on and make no outside requests. Set ``SCRAPLING_TEST_CHROME`` to a Chrome/Chromium
binary to run them; otherwise Patchright's own Chromium is used if installed.
"""

import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import pytest_asyncio

from scrapling.engines.antibot.solvers import (
    Token,
    find_widgets,
    inject_token,
    install_capture,
    read_captured,
    token_request,
)
from scrapling.engines.antibot.solvers.inject import (
    _parse_frame_url,
    capture_script,
    evaluate_main_world,
    inject_hcaptcha,
    inject_recaptcha,
    inject_turnstile,
    set_aws_waf_cookie,
)

# ---- pure helpers ------------------------------------------------------------------------------------------------


def test_parse_frame_urls():
    ts = _parse_frame_url(
        "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/b/turnstile/if/ov2/av0/rcv0/0/abc12/0x4AAAAAAABUYP0XeMJF0xoy/auto/fbE/new/normal/auto/"
    )
    assert ts == {"vendor": "turnstile", "sitekey": "0x4AAAAAAABUYP0XeMJF0xoy", "source": "frame"}
    test_key = _parse_frame_url(
        "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/g/turnstile/f/av0/rch/cwv6e/1x00000000000000000000AA/auto"
    )
    assert test_key["sitekey"] == "1x00000000000000000000AA"
    rc = _parse_frame_url(
        "https://www.google.com/recaptcha/enterprise/anchor?ar=1&k=6LcKEY&co=aHR0&hl=en&v=x&size=invisible&s=SVAL"
    )
    assert (
        rc["vendor"] == "recaptcha"
        and rc["sitekey"] == "6LcKEY"
        and rc["enterprise"]
        and rc["invisible"]
        and rc["data_s"] == "SVAL"
    )
    rcnet = _parse_frame_url("https://www.recaptcha.net/recaptcha/api2/anchor?k=6LcNET&size=normal")
    assert rcnet["api_domain"] == "recaptcha.net" and not rcnet["enterprise"]
    hc = _parse_frame_url(
        "https://newassets.hcaptcha.com/captcha/v1/abc/static/hcaptcha.html#frame=checkbox&id=0&sitekey=10000000-ffff-ffff-ffff-000000000001"
    )
    assert hc["vendor"] == "hcaptcha" and hc["sitekey"] == "10000000-ffff-ffff-ffff-000000000001"
    fc = _parse_frame_url("https://client-api.arkoselabs.com/fc/gc/?token=1&pk=6220FF23-9856-3A6F-9FF1-A14F88123F55")
    assert fc["vendor"] == "funcaptcha" and fc["funcaptcha_subdomain"] == "client-api.arkoselabs.com"
    assert _parse_frame_url("https://example.com/") is None
    assert _parse_frame_url("about:blank") is None


def test_token_request_mapping():
    page = "https://example.com/x"
    assert token_request({"vendor": "turnstile", "sitekey": "0xK", "action": "login", "cdata": "c"}, page) == {
        "kind": "turnstile",
        "sitekey": "0xK",
        "page_url": page,
        "action": "login",
        "cdata": "c",
    }
    assert (
        token_request(
            {"vendor": "turnstile", "sitekey": "0xK", "page_data": "p", "cdata": "c", "action": "managed"}, page
        )["kind"]
        == "turnstile_challenge"
    )
    assert token_request(
        {"vendor": "recaptcha", "version": "v3", "sitekey": "6L", "action": "home", "enterprise": True}, page
    ) == {"kind": "recaptcha_v3_enterprise", "sitekey": "6L", "page_url": page, "action": "home"}
    v2e = token_request(
        {"vendor": "recaptcha", "version": "v2", "sitekey": "6L", "enterprise": True, "data_s": "S", "invisible": True},
        page,
    )
    assert v2e == {
        "kind": "recaptcha_v2_enterprise",
        "sitekey": "6L",
        "page_url": page,
        "invisible": True,
        "enterprise_payload": {"s": "S"},
    }
    assert token_request({"vendor": "hcaptcha", "sitekey": "h"}, page)["kind"] == "hcaptcha"
    assert token_request({"vendor": "funcaptcha", "sitekey": "f", "funcaptcha_subdomain": "x.arkoselabs.com"}, page)[
        "funcaptcha_subdomain"
    ]
    with pytest.raises(ValueError):
        token_request({"vendor": "datadome", "sitekey": "x"}, page)


def test_capture_script_namespace_is_escaped():
    script = capture_script('a"b')
    assert 'const NS = "a\\"b";' in script


# ---- browser tests -----------------------------------------------------------------------------------------------

FAKE_TURNSTILE = """
(function () {
  if ('turnstile' in window) return;  // the real loader also skips itself when the global already exists
  var api = {
    render: function (el, opts) {
      var c = typeof el === 'string' ? document.querySelector(el) : el;
      var i = document.createElement('input'); i.type = 'hidden';
      i.name = (opts && opts['response-field-name']) || 'cf-turnstile-response';
      c.appendChild(i); return 'w-' + Math.random();
    },
    getResponse: function () { return ''; },
  };
  window.turnstile = api;
  document.querySelectorAll('.cf-turnstile').forEach(function (el) {  // implicit widgets do not go through window.turnstile.render
    var i = document.createElement('input'); i.type = 'hidden'; i.name = 'cf-turnstile-response'; el.appendChild(i);
  });
  // Like api.js: call the ?onload= callback right after defining window.turnstile, in the same task.
  var m = /[?&]onload=([^&]+)/.exec(document.currentScript.src);
  if (m && typeof window[m[1]] === 'function') window[m[1]]();
})();
"""

TURNSTILE_PAGE = """<!doctype html><html><body>
<form><div id="ts"></div><div id="ts2"></div></form>
<div class="cf-turnstile" data-sitekey="0x4AAAAAAAIMPLICIT0000" data-action="signup" data-callback="onImplicit"></div>
<script>
  window.onImplicit = function (t) { window.__implicit = t; };
  window.onTsLoad = function () {
    turnstile.render('#ts', { sitekey: '0x4AAAAAAATESTKEY00000', action: 'managed', cData: 'cdata-1', chlPageData: 'pd-1',
                              callback: function (t) { window.__explicit = t; } });
    turnstile.render('#ts2', { sitekey: '0x4AAAAAAASECONDKEY000', 'response-field-name': 'captcha_token', callback: 'onSecond' });
  };
  window.onSecond = function (t) { window.__second = t; };
</script>
<script src="/turnstile/v0/api.js?render=explicit&onload=onTsLoad"></script>
</body></html>"""

FAKE_RECAPTCHA = """
(function () {
if (window.___fake_rc) return;  // the page loads api.js twice (explicit widgets + a v3 key)
window.___fake_rc = true;
var onload = (/[?&]onload=([^&]+)/.exec(document.currentScript.src) || [])[1];
window.grecaptcha = window.grecaptcha || {};
grecaptcha.ready = function (cb) { setTimeout(cb, 0); };
setTimeout(function () {  // second stage, like recaptcha__en.js: define the API, then call ?onload= in the same task
  var clients = {}, n = 0;
  window.___grecaptcha_cfg = { clients: clients };
  function internalRender(el, opts) {
    var c = typeof el === 'string' ? document.getElementById(el) : el;
    var ta = document.createElement('textarea');
    ta.name = 'g-recaptcha-response'; ta.id = n ? 'g-recaptcha-response-' + n : 'g-recaptcha-response'; ta.style.display = 'none';
    c.appendChild(ta);
    clients[n] = { Xy: { Zq: { sitekey: opts.sitekey, callback: opts.callback, size: opts.size } } };
    return n++;
  }
  grecaptcha.render = function (el, opts) { return internalRender(el, opts); };
  grecaptcha.getResponse = function () { return ''; };
  grecaptcha.execute = function () { return Promise.resolve('real-v3-token'); };
  document.querySelectorAll('.g-recaptcha').forEach(function (el) {
    internalRender(el, { sitekey: el.getAttribute('data-sitekey'), callback: el.getAttribute('data-callback') });
  });
  if (onload && typeof window[onload] === 'function') window[onload]();
}, 30);
})();
"""

RECAPTCHA_PAGE = """<!doctype html><html><body>
<div id="rc"></div>
<div class="g-recaptcha" data-sitekey="6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI" data-callback="onImplicit"></div>
<script>
  window.onImplicit = function (t) { window.__implicit = t; };
  window.onRcLoad = function () {
    grecaptcha.render('rc', { sitekey: '6LcEXPLICITKEY00000000000000000000000000', size: 'invisible',
                              callback: function (t) { window.__explicit = t; } });
    grecaptcha.execute('6LcV3KEY000000000000000000000000000000000', { action: 'homepage' });
  };
</script>
<script src="/recaptcha/api.js?onload=onRcLoad&render=explicit"></script>
<script src="/recaptcha/api.js?render=6LcV3KEY000000000000000000000000000000000"></script>
</body></html>"""

FAKE_HCAPTCHA = """
window.hcaptcha = {
  render: function (el, opts) {
    var c = typeof el === 'string' ? document.getElementById(el) : el;
    ['h-captcha-response', 'g-recaptcha-response'].forEach(function (name) {
      var ta = document.createElement('textarea'); ta.name = name; ta.style.display = 'none'; c.appendChild(ta);
    });
    var f = document.createElement('iframe'); f.setAttribute('data-hcaptcha-response', ''); c.appendChild(f);
    return 'h-1';
  },
  getResponse: function () { return ''; },
};
window.grecaptcha = window.hcaptcha;  // reCAPTCHA compatibility alias, on by default in the real api.js
document.querySelectorAll('.h-captcha').forEach(function (el) {
  hcaptcha.render(el, { sitekey: el.getAttribute('data-sitekey'), callback: el.getAttribute('data-callback') });
});
if (window.onHcLoad) setTimeout(window.onHcLoad, 150);
"""

HCAPTCHA_PAGE = """<!doctype html><html><body>
<div class="h-captcha" data-sitekey="10000000-ffff-ffff-ffff-000000000001" data-callback="onH"></div>
<div id="hc2"></div>
<script>
  window.onH = function (t) { window.__h = t; };
  window.onHcLoad = function () {
    hcaptcha.render('hc2', { sitekey: '20000000-ffff-ffff-ffff-000000000002', callback: function (t) { window.__h2 = t; } });
  };
</script>
<script src="/fake-hcaptcha.js"></script>
</body></html>"""

ROUTES = {
    "/turnstile.html": ("text/html", TURNSTILE_PAGE),
    "/turnstile/v0/api.js": ("application/javascript", FAKE_TURNSTILE),
    "/recaptcha.html": ("text/html", RECAPTCHA_PAGE),
    "/recaptcha/api.js": ("application/javascript", FAKE_RECAPTCHA),
    "/hcaptcha.html": ("text/html", HCAPTCHA_PAGE),
    "/fake-hcaptcha.js": ("application/javascript", FAKE_HCAPTCHA),
}


class _Pages(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        content_type, body = ROUTES.get(self.path.split("?")[0], ("text/plain", None))
        data = (body or "not found").encode()
        self.send_response(200 if body is not None else 404)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


@pytest.fixture
def site():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Pages)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def _chrome():
    path = os.environ.get("SCRAPLING_TEST_CHROME")
    return path if path and os.path.exists(path) else None


@pytest_asyncio.fixture
async def browser_page():
    patchright = pytest.importorskip("patchright.async_api")
    async with patchright.async_playwright() as p:
        try:
            # Headless and sandboxed: nothing appears on screen and the renderer stays confined.
            browser = await p.chromium.launch(
                executable_path=_chrome(), headless=True, chromium_sandbox=True, args=["--mute-audio"]
            )
        except Exception as e:  # pragma: no cover - no browser available
            pytest.skip(f"no browser available: {type(e).__name__}")
        context = await browser.new_context()
        page = await context.new_page()
        try:
            yield context, page
        finally:
            await browser.close()


async def _main(page, expression):
    return await evaluate_main_world(page, expression)


@pytest.mark.asyncio
async def test_turnstile_capture_and_injection(site, browser_page):
    context, page = browser_page
    await install_capture(context)
    await page.goto(f"{site}/turnstile.html")
    await page.wait_for_function("() => document.querySelectorAll('input[name=cf-turnstile-response]').length >= 2")

    captured = await read_captured(page)
    assert [w["sitekey"] for w in captured["turnstile"]] == ["0x4AAAAAAATESTKEY00000", "0x4AAAAAAASECONDKEY000"]
    first = captured["turnstile"][0]
    assert (first["action"], first["cdata"], first["page_data"], first["callback"]) == (
        "managed",
        "cdata-1",
        "pd-1",
        "function",
    )

    widgets = {w["sitekey"]: w for w in await find_widgets(page)}
    assert set(widgets) == {"0x4AAAAAAATESTKEY00000", "0x4AAAAAAASECONDKEY000", "0x4AAAAAAAIMPLICIT0000"}
    assert (
        widgets["0x4AAAAAAAIMPLICIT0000"]["source"] == "dom" and widgets["0x4AAAAAAAIMPLICIT0000"]["action"] == "signup"
    )
    assert token_request(widgets["0x4AAAAAAATESTKEY00000"], page.url)["kind"] == "turnstile_challenge"

    only_second = await inject_turnstile(page, "ONLY-SECOND", sitekey="0x4AAAAAAASECONDKEY000")
    assert only_second["callbacks"] == 1
    assert await _main(page, "() => [window.__explicit, window.__second, window.__implicit]") == [
        None,
        "ONLY-SECOND",
        None,
    ]

    token = Token("TS-TOKEN-123", kind="turnstile", provider="test")
    result = await inject_token(page, token)
    assert result["callbacks"] == 3 and not result["errors"]
    assert result["fields"] == 3  # two cf-turnstile-response inputs + the custom "captcha_token" field
    state = await _main(
        page,
        "() => [window.__explicit, window.__second, window.__implicit, turnstile.getResponse('x'),"
        " document.querySelector('input[name=captcha_token]').value]",
    )
    assert state == ["TS-TOKEN-123"] * 5
    # The capture state is not an enumerable window property.
    assert await _main(page, "() => Object.keys(window).filter(k => k.startsWith('__') && k.length === 12).length") == 0


@pytest.mark.asyncio
async def test_recaptcha_capture_and_injection(site, browser_page):
    context, page = browser_page
    await install_capture(context)
    await page.goto(f"{site}/recaptcha.html")
    await page.wait_for_function("() => document.querySelectorAll('textarea[name=g-recaptcha-response]').length >= 2")

    widgets = await find_widgets(page)
    by_key = {(w["sitekey"], w.get("version")): w for w in widgets}
    explicit = by_key[("6LcEXPLICITKEY00000000000000000000000000", "v2")]
    assert explicit["source"] == "render" and explicit["invisible"] is True and explicit["callback"] == "function"
    assert by_key[("6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI", "v2")]["source"] == "dom"
    v3 = by_key[("6LcV3KEY000000000000000000000000000000000", "v3")]
    assert v3["action"] == "homepage"  # from the captured grecaptcha.execute call
    assert token_request(v3, page.url)["kind"] == "recaptcha_v3"

    only_implicit = await inject_recaptcha(page, "ONLY-IMPLICIT", sitekey="6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI")
    assert only_implicit["callbacks"] == 1
    assert await _main(page, "() => [window.__explicit, window.__implicit]") == [None, "ONLY-IMPLICIT"]

    result = await inject_recaptcha(page, "RC-TOKEN-456")
    assert result["fields"] == 2 and result["callbacks"] == 2 and not result["errors"]
    state = await _main(
        page,
        "async () => [window.__explicit, window.__implicit, grecaptcha.getResponse(), await grecaptcha.execute('k', {action: 'x'})]",
    )
    assert state == ["RC-TOKEN-456"] * 4


@pytest.mark.asyncio
async def test_hcaptcha_capture_with_recaptcha_alias(site, browser_page):
    context, page = browser_page
    await install_capture(context)
    await page.goto(f"{site}/hcaptcha.html")
    await page.wait_for_function("() => document.querySelectorAll('textarea[name=h-captcha-response]').length >= 2")
    captured = await read_captured(page)
    assert captured["recaptcha"] == []  # the grecaptcha alias is not mistaken for reCAPTCHA
    assert [w["sitekey"] for w in captured["hcaptcha"]] == ["20000000-ffff-ffff-ffff-000000000002"]
    widgets = await find_widgets(page)
    assert {(w["vendor"], w["sitekey"]) for w in widgets} == {
        ("hcaptcha", "10000000-ffff-ffff-ffff-000000000001"),
        ("hcaptcha", "20000000-ffff-ffff-ffff-000000000002"),
    }
    result = await inject_hcaptcha(page, "H2", sitekey="20000000-ffff-ffff-ffff-000000000002")
    assert result["callbacks"] == 1
    assert await _main(page, "() => [window.__h, window.__h2]") == [None, "H2"]


@pytest.mark.asyncio
async def test_hcaptcha_injection_without_capture(site, browser_page):
    _, page = browser_page
    await page.goto(f"{site}/hcaptcha.html")  # no capture script: DOM discovery and data-callback still work
    await page.wait_for_function("() => document.querySelectorAll('textarea[name=h-captcha-response]').length >= 2")
    widgets = await find_widgets(page)
    assert widgets == [
        {
            "vendor": "hcaptcha",
            "sitekey": "10000000-ffff-ffff-ffff-000000000001",
            "invisible": False,
            "callback": "onH",
            "source": "dom",
        }
    ]
    result = await inject_hcaptcha(page, "H-TOKEN-789")
    assert result["fields"] == 6 and result["callbacks"] == 1  # two widgets x (2 textareas + iframe attribute)
    assert (
        await _main(
            page,
            "() => [window.__h, hcaptcha.getResponse(), document.querySelector('iframe').getAttribute('data-hcaptcha-response')]",
        )
        == ["H-TOKEN-789"] * 3
    )


@pytest.mark.asyncio
async def test_inject_turnstile_without_widget_is_harmless(site, browser_page):
    _, page = browser_page
    await page.goto(f"{site}/hcaptcha.html")
    assert await inject_turnstile(page, "x") == {"fields": 0, "callbacks": 0, "errors": []}
    await set_aws_waf_cookie(page, "AWS-TOKEN", site + "/")
    cookies = await page.context.cookies()
    assert any(c["name"] == "aws-waf-token" and c["value"] == "AWS-TOKEN" for c in cookies)
    with pytest.raises(ValueError):
        await inject_token(page, "x", kind="geetest_v4")
