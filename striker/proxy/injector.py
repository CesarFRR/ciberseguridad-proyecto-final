"""Striker proxy: reverse proxy + HTML injection."""
import re
import urllib.parse
from io import BytesIO

import requests
from flask import Response, request as flask_request


# ── Constantes ────────────────────────────────────────────────────
HTML_TYPES = {"text/html", "application/xhtml+xml"}

INJECT_SCRIPT = """
<!-- ▸▸▸ STRIKER Navigation + Fetch Interceptor ▸▸▸ -->
<script>
(function(){
  var TARGET=new URLSearchParams(window.location.search).get('target')||'';
  if(TARGET){
    // Intercept fetch/XHR
    var _fetch=window.fetch;
    window.fetch=function(url,opts){
      if(typeof url==='string'&&url.startsWith('/')&&!url.startsWith('/proxy')&&!url.startsWith('/__striker__')){
        url='/proxy?target='+encodeURIComponent(TARGET)+'&path='+encodeURIComponent(url);
      }
      return _fetch.call(this,url,opts);
    };
    var _open=XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open=function(method,url){
      if(typeof url==='string'&&url.startsWith('/')&&!url.startsWith('/proxy')&&!url.startsWith('/__striker__')){
        url='/proxy?target='+encodeURIComponent(TARGET)+'&path='+encodeURIComponent(url);
      }
      return _open.call(this,method,url);
    };

    // Notify parent of navigation
    function notifyNav(){
      var p=new URLSearchParams(window.location.search);
      var path=p.get('path')||'/';
      window.parent&&window.parent.postMessage({type:'nav_update',base:TARGET,path:path},'*');
    }
    // Override history API for SPAs
    var _push=history.pushState;history.pushState=function(){_push.apply(this,arguments);notifyNav()};
    var _replace=history.replaceState;history.replaceState=function(){_replace.apply(this,arguments);notifyNav()};
    window.addEventListener('popstate',notifyNav);
    // Notify on load
    window.addEventListener('load',notifyNav);
    notifyNav();
  }
})();
</script>
<script src="/__striker__/element_selector.js?v=9"></script>
"""


# ── URL parsing ───────────────────────────────────────────────────
def get_upstream_url():
    """Extrae el target de ?target=http://..."""
    t = flask_request.args.get("target", "").strip()
    if not t:
        return None
    if not t.startswith(("http://", "https://")):
        t = "http://" + t
    return t.rstrip("/")


# ── Injection ─────────────────────────────────────────────────────
def should_inject(content_type):
    ct = (content_type or "").split(";")[0].strip().lower()
    return ct in HTML_TYPES


def inject_script(html_bytes, target_url):
    """Inyecta el selector visual, base tag y reescribe rutas absolutas"""
    html = html_bytes.decode("utf-8", errors="replace")
    encoded_target = urllib.parse.quote(target_url, safe="")

    # 0. Inyectar <base> para que rutas relativas pasen por el proxy
    base_tag = f'<base href="/proxy?target={encoded_target}&path=/">'
    head_close = re.compile(r"(</head>)", re.IGNORECASE)
    if head_close.search(html):
        html = head_close.sub(base_tag + r"\1", html, count=1)
    else:
        html = base_tag + html

    # 1. Re-escribir src/href/action absolutos al proxy
    encoded_target = urllib.parse.quote(target_url, safe="")

    def rewrite_path(match):
        attr = match.group(1)
        path = match.group(2)
        skip_prefixes = ("http://", "https://", "#", "data:", "javascript:", "//", "/proxy")
        if path.startswith(skip_prefixes):
            return match.group(0)
        encoded_path = urllib.parse.quote(path, safe="/?=&")
        return f'{attr}="/proxy?target={encoded_target}&path={encoded_path}"'

    html = re.sub(
        r'(src|href|action)\s*=\s*"([^"]+)"',
        rewrite_path, html, flags=re.IGNORECASE,
    )
    html = re.sub(
        r"(src|href|action)\s*=\s*'([^']+)'",
        rewrite_path, html, flags=re.IGNORECASE,
    )

    # 2. Inyectar el selector antes del último </body>
    body_close = re.compile(r"(</body>)", re.IGNORECASE)
    matches = list(body_close.finditer(html))
    if matches:
        last = matches[-1]
        html = html[:last.start()] + INJECT_SCRIPT + html[last.start():]
    else:
        html += INJECT_SCRIPT

    return html.encode("utf-8")
