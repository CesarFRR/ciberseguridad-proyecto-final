#!/usr/bin/env python3
"""
VulnTest Platform — Challenges de seguridad para Striker DAST.
Cada ruta es una vulnerabilidad distinta. NO USAR EN PRODUCCIÓN.
"""

import sqlite3, subprocess, os, threading, time, json
from flask import Flask, render_template_string, request, jsonify, session, redirect

app = Flask(__name__)
app.config["SECRET_KEY"] = "vuln-test-secret-2024"

# ── SQLite DB (para SQLi) ────────────────────────────────────────
DB_PATH = "/tmp/vulntest.db"

def init_db():
    if os.path.exists(DB_PATH): os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, role TEXT)")
    c.execute("INSERT INTO users VALUES (1,'admin','supersecret123','admin@vulntest.local','admin')")
    c.execute("INSERT INTO users VALUES (2,'alice','alice2024','alice@test.com','user')")
    c.execute("INSERT INTO users VALUES (3,'bob','bob12345','bob@test.com','user')")
    c.execute("INSERT INTO users VALUES (4,'guest','guest','guest@test.com','guest')")
    conn.commit()
    conn.close()

init_db()

# ── Datos falsos para NoSQL testing ──────────────────────────────
NOSQL_DB = [
    {"username": "admin", "password": "supersecret123", "role": "admin"},
    {"username": "alice", "password": "alice2024", "role": "user"},
]

# ── Comentarios almacenados (XSS stored) ─────────────────────────
COMMENTS = []

# ── Rate limit tracking (DDoS) ───────────────────────────────────
REQUEST_LOG = {}
RATE_LIMIT = 100  # requests per second per IP triggers alert

# ═══════════════════════════════════════════════════════════════════
#  HOME
# ═══════════════════════════════════════════════════════════════════

HOME = """<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><title>VulnTest Platform</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--accent:#58a6ff;--text:#c9d1d9;--red:#f85149;--green:#3fb950;--amber:#d2991d}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;padding:20px}
h1{font-size:24px;color:var(--accent);text-align:center;padding:20px 0 8px}
.subtitle{text-align:center;color:#8b949e;font-size:13px;margin-bottom:30px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px;max-width:1200px;margin:0 auto}
.challenge{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:20px;transition:border-color .2s}
.challenge:hover{border-color:var(--accent)}
.challenge h3{font-size:15px;margin-bottom:4px}
.challenge .tag{display:inline-block;font-size:9px;padding:1px 6px;border-radius:3px;font-weight:600;text-transform:uppercase;margin-right:4px}
.tag.owasp{background:rgba(248,81,73,.15);color:var(--red)}
.tag.mitre{background:rgba(88,166,255,.15);color:var(--accent)}
.tag.cwe{background:rgba(210,153,29,.15);color:var(--amber)}
.challenge .desc{font-size:12px;color:#8b949e;margin:8px 0 12px;line-height:1.5}
.challenge a{display:inline-block;background:var(--accent);color:white;padding:6px 16px;border-radius:4px;text-decoration:none;font-size:12px;font-weight:600}.challenge a:hover{opacity:.8}
</style>
</head>
<body>
<h1>VulnTest Platform</h1>
<p class="subtitle">Plataforma de challenges para Striker DAST · NO USAR EN PRODUCCIÓN</p>
<div class="grid">
  <div class="challenge">
    <h3>🔴 SQL Injection</h3>
    <span class="tag owasp">A03 Injection</span><span class="tag mitre">T1190</span><span class="tag cwe">CWE-89</span>
    <p class="desc">Login vulnerable a SQLi con base SQLite real. Bypass de autenticación, UNION attacks, extracción de datos.</p>
    <a href="/sqli">Abrir challenge →</a>
  </div>
  <div class="challenge">
    <h3>🔴 NoSQL Injection</h3>
    <span class="tag owasp">A03 Injection</span><span class="tag mitre">T1190</span><span class="tag cwe">CWE-943</span>
    <p class="desc">API tipo MongoDB vulnerable a operadores $gt, $ne, $regex. Bypass de login sin contraseña.</p>
    <a href="/nosqli">Abrir challenge →</a>
  </div>
  <div class="challenge">
    <h3>🟠 XSS Level 1 — Reflected</h3>
    <span class="tag owasp">A03 Injection</span><span class="tag mitre">T1059.007</span><span class="tag cwe">CWE-79</span>
    <p class="desc">XSS reflejado clásico. El input del usuario se refleja en la página sin escape.</p>
    <a href="/xss/1">Abrir challenge →</a>
  </div>
  <div class="challenge">
    <h3>🟠 XSS — Final Challenge</h3>
    <span class="tag owasp">A03 Injection</span><span class="tag mitre">T1059.007</span><span class="tag cwe">CWE-79</span>
    <p class="desc">Todas las técnicas XSS en un solo reto: reflejado, almacenado, atributo, JS context, protocolo y filter bypass.</p>
    <a href="/xss">Abrir challenge →</a>
  </div>
  <div class="challenge">
    <h3>🔴 Command Injection</h3>
    <span class="tag owasp">A03 Injection</span><span class="tag mitre">T1059.004</span><span class="tag cwe">CWE-77</span>
    <p class="desc">Utilidad de ping vulnerable. Shell command injection vía campo de host.</p>
    <a href="/cmdi">Abrir challenge →</a>
  </div>
  <div class="challenge">
    <h3>🟡 Path Traversal</h3>
    <span class="tag owasp">A01 Access Control</span><span class="tag mitre">T1005</span><span class="tag cwe">CWE-22</span>
    <p class="desc">Visor de archivos sin validación de ruta. Lee /etc/passwd y otros archivos del sistema.</p>
    <a href="/pathtrav">Abrir challenge →</a>
  </div>
  <div class="challenge">
    <h3>🟡 DDoS Simulation</h3>
    <span class="tag owasp">A05 Misconfig</span><span class="tag mitre">T1499</span><span class="tag cwe">CWE-770</span>
    <p class="desc">Endpoint sin rate limiting. Simula tráfico masivo y observa cómo responde el servidor.</p>
    <a href="/ddos">Abrir challenge →</a>
  </div>
  <div class="challenge">
    <h3>🟢 Phishing Awareness</h3>
    <span class="tag mitre">T1566</span><span class="tag cwe">—</span>
    <p class="desc">Simulador de página de login falsa. Identifica elementos sospechosos en URLs y formularios.</p>
    <a href="/phishing">Abrir challenge →</a>
  </div>
</div>
</body>
</html>"""

@app.route("/")
def home():
    return HOME

# ═══════════════════════════════════════════════════════════════════
#  SQL INJECTION
# ═══════════════════════════════════════════════════════════════════

SQLI_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>SQL Injection Challenge</title>
<style>:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--accent:#58a6ff;--text:#c9d1d9;--red:#f85149}
body{font-family:system-ui;background:var(--bg);color:var(--text);display:flex;justify-content:center;padding:60px 20px}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:24px;width:400px}
h2{color:var(--red);margin-bottom:4px}h2 small{font-size:12px;font-weight:400;color:#8b949e}
input{width:100%;padding:8px 10px;margin:6px 0;background:#0d1117;border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:13px}
button{background:var(--accent);color:white;border:none;padding:8px 20px;border-radius:4px;cursor:pointer;font-weight:600;margin-top:8px}
.result{padding:8px;margin-top:8px;border-radius:4px;font-size:13px}
.result.ok{background:#0f3d0f;color:#3fb950}.result.err{background:#3d0f0f;color:var(--red)}
.result pre{font-size:11px;overflow-x:auto;margin:4px 0}
.hint{font-size:11px;color:#8b949e;margin-top:8px}a{color:var(--accent);font-size:11px}
</style></head>
<body>
<div class="card">
<h2>🔴 SQL Injection <small>Challenge</small></h2>
<form method="POST">
<input type="text" name="username" placeholder="Username" id="username">
<input type="password" name="password" placeholder="Password" id="password">
<button type="submit">Login</button>
</form>
{% if msg %}<div class="result {{ 'ok' if ok else 'err' }}">{{ msg | safe }}</div>{% endif %}
{% if data %}<div class="result ok"><pre>{{ data }}</pre></div>{% endif %}
<p class="hint">💡 Try: <code>' OR '1'='1</code> in username field</p>
<a href="/">← Back to challenges</a>
</div>
</body></html>"""

@app.route("/sqli", methods=["GET", "POST"])
def sqli():
    msg = ""; ok = False; data = ""
    if request.method == "POST":
        user = request.form.get("username", "")
        pwd = request.form.get("password", "")
        # VULNERABLE: concatenación directa en query SQL
        query = f"SELECT * FROM users WHERE username='{user}' AND password='{pwd}'"
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute(query)
            rows = c.fetchall()
            if rows:
                msg = f"✅ Welcome, {rows[0][1]}! (role: {rows[0][4]})"
                ok = True
                data = "\n".join([f"ID:{r[0]} | User:{r[1]} | Email:{r[3]} | Role:{r[4]}" for r in rows])
            else:
                msg = "❌ Invalid credentials"
            conn.close()
        except Exception as e:
            msg = f"SQL Error: {e}"
            ok = False
    return render_template_string(SQLI_HTML, msg=msg, ok=ok, data=data)

# ═══════════════════════════════════════════════════════════════════
#  NOSQL INJECTION
# ═══════════════════════════════════════════════════════════════════

NOSQLI_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>NoSQL Injection Challenge</title>
<style>:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--accent:#58a6ff;--text:#c9d1d9;--red:#f85149;--green:#3fb950}
body{font-family:system-ui;background:var(--bg);color:var(--text);display:flex;justify-content:center;padding:60px 20px}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:24px;width:400px}
h2{color:var(--red)}input{width:100%;padding:8px;margin:6px 0;background:#0d1117;border:1px solid var(--border);border-radius:4px;color:var(--text)}
button{background:var(--accent);color:white;border:none;padding:8px 20px;border-radius:4px;cursor:pointer;margin-top:8px}
.result{padding:8px;margin-top:8px;border-radius:4px;font-size:13px}.result.ok{background:#0f3d0f;color:var(--green)}.result.err{background:#3d0f0f;color:var(--red)}
.hint{font-size:11px;color:#8b949e;margin-top:8px}a{color:var(--accent);font-size:11px}
</style></head><body>
<div class="card">
<h2>🔴 NoSQL Injection <small>Challenge</small></h2>
<form method="POST">
<input type="text" name="username" id="username" placeholder="Username">
<input type="password" name="password" id="password" placeholder="Password">
<button type="submit">Login</button>
</form>
{% if msg %}<div class="result {{ 'ok' if ok else 'err' }}">{{ msg }}</div>{% endif %}
<p class="hint">💡 Try JSON injection: <code>{"$gt":""}</code> or <code>{"$ne":null}</code></p>
<a href="/">← Back</a>
</div></body></html>"""

@app.route("/nosqli", methods=["GET", "POST"])
def nosqli():
    msg = ""; ok = False
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # Simular consulta NoSQL vulnerable
        # Si el input se parece a JSON, intentar parsearlo
        query = {}
        try:
            if username.startswith("{") or username.startswith("["):
                query = json.loads(username)
            else:
                query = {"username": username, "password": password}
        except:
            query = {"username": username, "password": password}

        # VULNERABLE: matching manual simulando consulta NoSQL sin validación
        found = None
        for user in NOSQL_DB:
            match = True
            uq = query.get("username", username)
            pq = query.get("password", password)
            # Simular operadores NoSQL
            if isinstance(uq, dict) and "$gt" in uq:
                match = match and user["username"] > uq["$gt"]
            elif isinstance(uq, dict) and "$ne" in uq:
                match = match and user["username"] != uq["$ne"]
            elif isinstance(uq, dict) and "$regex" in uq:
                import re
                match = match and bool(re.search(uq["$regex"], user["username"]))
            else:
                match = match and user["username"] == str(uq)
            if isinstance(pq, dict) and "$gt" in pq:
                match = match and user["password"] > pq["$gt"]
            elif isinstance(pq, dict) and "$ne" in pq:
                match = match and user["password"] != pq["$ne"]
            else:
                match = match and user["password"] == str(pq)
            if match:
                found = user
                break

        if found:
            msg = f"✅ Welcome, {found['username']}! (role: {found['role']})"
            ok = True
        else:
            msg = "❌ Invalid credentials"
    return render_template_string(NOSQLI_HTML, msg=msg, ok=ok)

# ═══════════════════════════════════════════════════════════════════
#  XSS Level 1 — Reflected (simple)
# ═══════════════════════════════════════════════════════════════════

XSS1_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>XSS Level 1 — Reflected</title>
<style>:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--accent:#58a6ff;--text:#c9d1d9;--orange:#d2991d}
body{font-family:system-ui;background:var(--bg);color:var(--text);display:flex;justify-content:center;padding:60px 20px}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:24px;width:500px}
h2{color:var(--orange)}input{width:100%;padding:8px;background:#0d1117;border:1px solid var(--border);border-radius:4px;color:var(--text)}
button{background:var(--accent);color:white;border:none;padding:8px 20px;border-radius:4px;cursor:pointer}
.result{padding:8px;margin-top:12px;background:#161b22;border-radius:4px;font-size:13px;border:1px solid var(--border)}
.hint{font-size:11px;color:#8b949e;margin-top:8px}a{color:var(--accent);font-size:11px}
</style></head><body>
<div class="card">
<h2>🟠 XSS Level 1 — Reflected</h2>
<p style="color:#8b949e;font-size:12px;margin-bottom:12px">Tu búsqueda se refleja directamente en la página sin ningún filtro.</p>
<form method="GET">
<input type="text" name="q" placeholder="Search something...">
<button type="submit">Search</button>
</form>
{% if query %}
<div class="result">Results for: {{ query | safe }}</div>
{% endif %}
<p class="hint">💡 <code>&lt;script&gt;alert(1)&lt;/script&gt;</code> o <code>&lt;img src=x onerror=alert(1)&gt;</code></p>
<a href="/">← Back</a>
</div></body></html>"""

@app.route("/xss/1")
def xss1():
    q = request.args.get("q", "")
    return render_template_string(XSS1_HTML, query=q)

# ═══════════════════════════════════════════════════════════════════
#  XSS — FINAL CHALLENGE (todas las técnicas)
# ═══════════════════════════════════════════════════════════════════

XSS_FINAL_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>XSS Final Challenge</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--accent:#58a6ff;--text:#c9d1d9;--orange:#d2991d;--green:#3fb950}
body{font-family:system-ui;background:var(--bg);color:var(--text);padding:30px 20px}
h1{color:var(--orange);text-align:center;margin-bottom:4px}h1 small{font-size:14px;color:#8b949e;font-weight:400}
.sub{text-align:center;color:#8b949e;font-size:12px;margin-bottom:24px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(380px,1fr));gap:16px;max-width:1100px;margin:0 auto}
.box{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:20px}
.box h3{font-size:13px;color:var(--orange);margin-bottom:6px}
.box .technique{font-size:9px;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px}
.box input,.box textarea{width:100%;padding:7px 9px;margin:4px 0;background:#0d1117;border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:12px}
.box button{background:var(--accent);color:white;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;font-size:11px;font-weight:600;margin-top:4px}
.box button:hover{opacity:.8}
.box .result{padding:6px 8px;margin-top:8px;border-radius:4px;font-size:12px;background:#0d1117;border:1px solid var(--border);word-break:break-all}
.box .hint{font-size:10px;color:#8b949e;margin-top:6px}
.box .hint code{color:var(--accent);background:rgba(88,166,255,.1);padding:1px 4px;border-radius:2px}
pre{background:#0d1117;padding:10px;border-radius:4px;font-size:10px;overflow-x:auto;border:1px solid var(--border);margin:6px 0 0;color:#8b949e;display:none}
.show-code{font-size:9px;color:var(--accent);cursor:pointer;margin-top:4px;display:inline-block}
.show-code:hover{text-decoration:underline}
.comments{margin-top:12px;max-height:200px;overflow-y:auto}
.comment-box{background:#0d1117;border:1px solid var(--border);border-radius:4px;padding:6px 8px;margin:4px 0;font-size:11px}
.comment-box strong{color:var(--accent)}
a.back{color:var(--accent);font-size:11px;display:block;text-align:center;margin-top:20px}
</style></head><body>
<h1>🟠 XSS Final Challenge <small>· todas las técnicas</small></h1>
<p class="sub">6 vectores de XSS en un solo reto. Cada sección es vulnerable a una técnica distinta.</p>
<div class="grid">

  <!-- 1. Reflected XSS -->
  <div class="box">
    <h3>① Search (Reflected)</h3>
    <span class="technique">Reflected XSS</span>
    <form method="GET" action="/xss">
      <input type="text" name="search" placeholder="Search...">
      <button type="submit">Search</button>
    </form>
    {% if search %}<div class="result">{{ search | safe }}</div>{% endif %}
    <p class="hint">💡 <code>&lt;script&gt;alert(1)&lt;/script&gt;</code> o <code>&lt;img src=x onerror=alert(1)&gt;</code></p>
    <span class="show-code" onclick="this.nextElementSibling.style.display='block'">▼ Show code</span>
    <pre>results.innerHTML = "{{ search }}"; // sin escape</pre>
  </div>

  <!-- 2. Stored XSS -->
  <div class="box">
    <h3>② Comments (Stored)</h3>
    <span class="technique">Stored XSS</span>
    <form method="POST" action="/xss">
      <input type="text" name="cname" placeholder="Name">
      <textarea name="cmsg" rows="2" placeholder="Comment..."></textarea>
      <button type="submit">Post</button>
    </form>
    {% if comments %}
    <div class="comments">
    {% for c in comments %}
    <div class="comment-box"><strong>{{ c.name | safe }}:</strong> {{ c.msg | safe }}</div>
    {% endfor %}
    </div>
    {% endif %}
    <p class="hint">💡 <code>&lt;img src=x onerror=alert('stored')&gt;</code> — persiste al recargar</p>
    <span class="show-code" onclick="this.nextElementSibling.style.display='block'">▼ Show code</span>
    <pre>comment.innerHTML = "{{ msg }}"; // XSS almacenado sin sanitizar</pre>
  </div>

  <!-- 3. URL Hash Attribute Injection -->
  <div class="box">
    <h3>③ Image Viewer (Attribute)</h3>
    <span class="technique">HTML Attribute Injection via URL hash</span>
    <div id="xss-img-container">
      <img src="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 200 60'><rect fill='%23222' width='200' height='60'/><text x='100' y='35' text-anchor='middle' fill='%23888' font-size='12'>Image via URL hash</text></svg>" style="max-width:200px;border-radius:4px">
    </div>
    <p class="hint">💡 Add to URL: <code>#1' onerror='alert(1)</code> — inyecta atributo en &lt;img&gt;</p>
    <span class="show-code" onclick="this.nextElementSibling.style.display='block'">▼ Show code</span>
    <pre>el.innerHTML = '&lt;img src="/img/' + hash + '.jpg"&gt;';</pre>
  </div>

  <!-- 4. JavaScript Context -->
  <div class="box">
    <h3>④ Timer (JS Context)</h3>
    <span class="technique">JavaScript string injection</span>
    <form method="GET" action="/xss">
      <input type="text" name="timer" placeholder="Seconds" value="3">
      <button type="submit" name="start" value="1">Start Timer</button>
    </form>
    {% if timer_msg %}<div class="result" style="color:var(--green)">{{ timer_msg }}</div>{% endif %}
    <p class="hint">💡 <code>');alert(1);//</code> — cierra comillas, inyecta, comenta el resto</p>
    <span class="show-code" onclick="this.nextElementSibling.style.display='block'">▼ Show code</span>
    <pre>onload="startTimer('{{ timer }}');" // inyección en string JS</pre>
  </div>

  <!-- 5. JavaScript Protocol -->
  <div class="box">
    <h3>⑤ Next Page (JS Protocol)</h3>
    <span class="technique">javascript: protocol in href</span>
    {% if next_url %}
    <p style="color:var(--green);font-size:12px">✅ Done!</p>
    <a href="{{ next_url | safe }}" style="display:inline-block;background:var(--accent);color:white;padding:6px 16px;border-radius:4px;text-decoration:none;font-size:11px">Next →</a>
    {% else %}
    <p style="font-size:11px;color:#8b949e">Try: <code>/xss?next=javascript:alert(1)</code></p>
    {% endif %}
    <p class="hint" style="margin-top:8px">💡 <code>javascript:alert(1)</code> — el navegador ejecuta el protocolo</p>
    <span class="show-code" onclick="this.nextElementSibling.style.display='block'">▼ Show code</span>
    <pre>&lt;a href="{{ next }}"&gt;Next&lt;/a&gt; // javascript: es protocolo válido</pre>
  </div>

  <!-- 6. Filter Bypass -->
  <div class="box">
    <h3>⑥ Script Loader (Filter Bypass)</h3>
    <span class="technique">Data URI bypass</span>
    <div id="xss-filter-status" style="font-size:11px;color:#8b949e">Waiting for #hash in URL...</div>
    <p class="hint">💡 Add to URL: <code>#data:text/javascript,alert('bypass')</code></p>
    <span class="show-code" onclick="this.nextElementSibling.style.display='block'">▼ Show code</span>
    <pre>if (!url.match(/^https?:\\/\\//)) { script.src = url; } // data: URI bypassea</pre>
  </div>

</div>
<a class="back" href="/">← Back to challenges</a>

<!-- JS para vectores 3 y 6 (client-side) -->
<script>
// Vector 3: URL hash → attribute injection
(function(){
  var h = location.hash.slice(1);
  if (h) {
    var c = document.getElementById('xss-img-container');
    c.innerHTML = '<img src="data:image/svg+xml,<svg xmlns=\\'http://www.w3.org/2000/svg\\' viewBox=\\'0 0 200 60\\'><rect fill=\\'%23222\\' width=\\'200\\' height=\\'60\\'/><text x=\\'100\\' y=\\'35\\' text-anchor=\\'middle\\' fill=\\'%23888\\' font-size=\\'12\\'>Image: ' + h + '</text></svg>" style="max-width:200px;border-radius:4px">';
  }
})();

// Vector 6: Filter bypass via hash
(function(){
  var u = location.hash.slice(1);
  var s = document.getElementById('xss-filter-status');
  if (!u) return;
  if (u.match(/^https?:\\/\\//)) {
    s.innerHTML = '🚫 BLOCKED: http/https not allowed. Try data: URI.';
    s.style.color = '#f85149';
    return;
  }
  s.innerHTML = '⚡ Loading: ' + u.slice(0,50) + '...';
  s.style.color = '#3fb950';
  try {
    var sc = document.createElement('script');
    sc.src = u;
    document.body.appendChild(sc);
  } catch(e) { s.innerHTML = 'Error: ' + e.message; s.style.color = '#f85149'; }
})();
</script>
</body></html>"""

@app.route("/xss", methods=["GET", "POST"])
def xss_all():
    search = request.args.get("search", "")
    timer = request.args.get("timer", "")
    timer_msg = ""
    if request.args.get("start"):
        timer_msg = f"Timer started for {timer} seconds!"
    next_url = request.args.get("next", "")
    if request.method == "POST":
        COMMENTS.append({"name": request.form.get("cname", "Anon"), "msg": request.form.get("cmsg", "")})
    return render_template_string(
        XSS_FINAL_HTML,
        search=search,
        comments=COMMENTS,
        timer=timer,
        timer_msg=timer_msg,
        next_url=next_url,
    )

# ═══════════════════════════════════════════════════════════════════
#  COMMAND INJECTION
# ═══════════════════════════════════════════════════════════════════

CMDI_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Command Injection Challenge</title>
<style>:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--accent:#58a6ff;--text:#c9d1d9;--red:#f85149}
body{font-family:system-ui;background:var(--bg);color:var(--text);display:flex;justify-content:center;padding:60px 20px}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:24px;width:500px}
h2{color:var(--red)}input{width:100%;padding:8px;background:#0d1117;border:1px solid var(--border);border-radius:4px;color:var(--text)}
button{background:var(--accent);color:white;border:none;padding:8px 20px;border-radius:4px;cursor:pointer}
pre{background:#0d1117;padding:12px;border-radius:4px;font-size:12px;overflow-x:auto;margin-top:8px;border:1px solid var(--border)}
.hint{font-size:11px;color:#8b949e;margin-top:8px}a{color:var(--accent);font-size:11px}
</style></head><body>
<div class="card">
<h2>🔴 Command Injection <small>Challenge</small></h2>
<p style="color:#8b949e;font-size:12px;margin-bottom:12px">Utilidad de red — ping a un host.</p>
<form method="GET">
<input type="text" name="host" id="host" placeholder="8.8.8.8" value="127.0.0.1">
<button type="submit">Ping</button>
</form>
{% if result %}<pre>{{ result }}</pre>{% endif %}
<p class="hint">💡 Try: <code>127.0.0.1; ls -la</code> or <code>8.8.8.8 && whoami</code></p>
<a href="/">← Back</a>
</div></body></html>"""

@app.route("/cmdi")
def cmdi():
    host = request.args.get("host", "")
    result = ""
    if host:
        # VULNERABLE: shell=True con input directo
        cmd = f"ping -c 2 -W 1 {host}"
        try:
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=4)
            result = result.decode(errors="replace")
        except subprocess.TimeoutExpired:
            result = "Timeout"
        except Exception as e:
            result = f"Error: {e}"
    return render_template_string(CMDI_HTML, result=result)

# ═══════════════════════════════════════════════════════════════════
#  PATH TRAVERSAL
# ═══════════════════════════════════════════════════════════════════

PATHTRAV_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Path Traversal Challenge</title>
<style>:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--accent:#58a6ff;--text:#c9d1d9;--amber:#d2991d}
body{font-family:system-ui;background:var(--bg);color:var(--text);display:flex;justify-content:center;padding:60px 20px}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:24px;width:500px}
h2{color:var(--amber)}input{width:100%;padding:8px;background:#0d1117;border:1px solid var(--border);border-radius:4px;color:var(--text)}
button{background:var(--accent);color:white;border:none;padding:8px 20px;border-radius:4px;cursor:pointer}
pre{background:#0d1117;padding:12px;border-radius:4px;font-size:12px;overflow-x:auto;margin-top:8px;border:1px solid var(--border)}
.hint{font-size:11px;color:#8b949e;margin-top:8px}a{color:var(--accent);font-size:11px}
</style></head><body>
<div class="card">
<h2>🟡 Path Traversal <small>Challenge</small></h2>
<p style="color:#8b949e;font-size:12px;margin-bottom:12px">Visor de archivos del sistema. ¿Qué tan lejos puedes llegar?</p>
<form method="GET">
<input type="text" name="file" id="file" placeholder="test.txt" value="/etc/hostname">
<button type="submit">View File</button>
</form>
{% if content %}<pre>{{ content }}</pre>{% endif %}
{% if error %}<pre style="color:var(--red)">{{ error }}</pre>{% endif %}
<p class="hint">💡 Try: <code>../../../../etc/passwd</code> or <code>/etc/shadow</code></p>
<a href="/">← Back</a>
</div></body></html>"""

@app.route("/pathtrav")
def pathtrav():
    filename = request.args.get("file", "")
    content = ""; error = ""
    if filename:
        try:
            with open(filename, "r") as f:
                content = f.read(1000)
        except PermissionError:
            error = "Permission denied"
        except FileNotFoundError:
            error = "File not found"
        except Exception as e:
            error = str(e)
    return render_template_string(PATHTRAV_HTML, content=content, error=error)

# ═══════════════════════════════════════════════════════════════════
#  DDoS SIMULATION
# ═══════════════════════════════════════════════════════════════════

DDOS_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>DDoS Simulation</title>
<style>:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--accent:#58a6ff;--text:#c9d1d9;--amber:#d2991d}
body{font-family:system-ui;background:var(--bg);color:var(--text);display:flex;justify-content:center;padding:60px 20px}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:24px;width:500px}
h2{color:var(--amber)}.stats{display:flex;gap:16px;margin:12px 0}
.stat{background:#0d1117;border:1px solid var(--border);border-radius:4px;padding:12px;text-align:center;flex:1}
.stat .val{font-size:28px;font-weight:700;color:var(--accent);font-family:monospace}
.stat .lbl{font-size:10px;color:#8b949e;text-transform:uppercase;letter-spacing:.05em}
.bar-bg{height:4px;background:#0d1117;border-radius:2px;margin:8px 0;overflow:hidden}
.bar-fg{height:100%;border-radius:2px;transition:width .3s}
.hint{font-size:11px;color:#8b949e;margin-top:8px}a{color:var(--accent);font-size:11px}
</style></head><body>
<div class="card">
<h2>🟡 DDoS Simulation <small>Endpoint sin rate limiting</small></h2>
<div class="stats">
<div class="stat"><div class="val" id="rps">0</div><div class="lbl">Requests / sec</div></div>
<div class="stat"><div class="val" id="total">0</div><div class="lbl">Total Requests</div></div>
</div>
<div class="bar-bg"><div class="bar-fg" id="bar" style="width:0%;background:var(--accent)"></div></div>
<p style="font-size:11px;color:#8b949e">Cada refresh = 1 request. Usa <code>wrk -t4 -c100 -d10s http://localhost:5005/ddos/api</code></p>
<a href="/">← Back</a>
</div>
<script>
let total=0;
setInterval(async()=>{
total++;document.getElementById('total').textContent=total;
try{const r=await fetch('/ddos/api/count');const d=await r.json();
document.getElementById('rps').textContent=d.rps;
const bar=document.getElementById('bar');
bar.style.width=Math.min(d.rps*2,100)+'%';
bar.style.background=d.rps>20?'#f85149':d.rps>10?'#d2991d':'#58a6ff';
}catch(_){}
},1000);
</script>
</div></body></html>"""

# Track para DDoS
ddos_counter = {"requests": 0, "last_reset": time.time()}
ddos_lock = threading.Lock()

@app.route("/ddos")
def ddos_page():
    return DDOS_HTML

@app.route("/ddos/api")
def ddos_api():
    """Endpoint sin rate limiting — vulnerable a DDoS"""
    with ddos_lock:
        ddos_counter["requests"] += 1
    # CPU burn intencional para simular carga
    _ = sum(i*i for i in range(1000))
    return jsonify({"status": "ok", "request": ddos_counter["requests"]})

@app.route("/ddos/api/count")
def ddos_count():
    now = time.time()
    with ddos_lock:
        elapsed = now - ddos_counter["last_reset"]
        if elapsed >= 1.0:
            rps = ddos_counter["requests"] / elapsed
            ddos_counter["requests"] = 0
            ddos_counter["last_reset"] = now
        else:
            rps = 0
    return jsonify({"rps": round(rps, 1)})

# ═══════════════════════════════════════════════════════════════════
#  PHISHING AWARENESS
# ═══════════════════════════════════════════════════════════════════

PHISHING_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Phishing Awareness</title>
<style>:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--accent:#58a6ff;--text:#c9d1d9;--green:#3fb950}
body{font-family:system-ui;background:var(--bg);color:var(--text);display:flex;justify-content:center;padding:60px 20px}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:24px;width:500px}
h2{color:var(--green)}.fake-login{background:#fff;border-radius:8px;padding:24px;color:#1a1a1a;margin:12px 0}
.fake-login img{width:80px;display:block;margin:0 auto 12px}
.fake-login h3{text-align:center;color:#333;font-size:16px}
.fake-login input{width:100%;padding:10px;margin:6px 0;border:1px solid #ddd;border-radius:4px;font-size:14px}
.fake-login button{width:100%;background:#1877f2;color:white;border:none;padding:10px;border-radius:4px;font-weight:600;font-size:14px;cursor:pointer}
.red-flags{background:#0d1117;border:1px solid var(--border);border-radius:4px;padding:12px;margin-top:12px;font-size:12px}
.red-flags li{margin:4px 0;color:#8b949e}
.hint{font-size:11px;color:#8b949e;margin-top:8px}a{color:var(--accent);font-size:11px}
</style></head><body>
<div class="card">
<h2>🟢 Phishing Awareness <small>Demo</small></h2>
<p style="color:#8b949e;font-size:12px;margin-bottom:12px">Simulación de página de login falsa. Identifica las señales de phishing.</p>
<div class="fake-login">
<img src="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 48 48'><circle cx='24' cy='24' r='22' fill='%231877f2'/><text x='24' y='30' text-anchor='middle' fill='white' font-size='24' font-weight='bold' font-family='sans-serif'>f</text></svg>" alt="Facebook logo" width="60" height="60">
<h3>Log in to Facebook</h3>
<form method="POST" action="/phishing/capture">
<input type="text" name="email" id="email" placeholder="Email or phone number">
<input type="password" name="pass" id="pass" placeholder="Password">
<button type="submit">Log In</button>
</form>
</div>
{% if captured %}
<div class="red-flags" style="border-color:var(--green)">
<p style="color:var(--green);font-weight:600">⚠️ ¡Caíste en el simulacro!</p>
<p>Credenciales capturadas: <strong style="color:var(--red)">{{ captured }}</strong></p>
<p>Esto es un simulacro educativo. En un ataque real, tus credenciales habrían sido robadas.</p>
</div>
{% endif %}
<div class="red-flags">
<p style="font-weight:600;color:var(--amber)">🚩 Señales de phishing:</p>
<ul>
<li>URL sospechosa (no es facebook.com)</li>
<li>Sin candado HTTPS verde</li>
<li>Logo de baja calidad</li>
<li>Urgencia: "Tu cuenta será suspendida"</li>
<li>Errores gramaticales</li>
</ul>
</div>
<a href="/">← Back</a>
</div></body></html>"""

@app.route("/phishing", methods=["GET", "POST"])
def phishing():
    captured = ""
    if request.method == "POST":
        email = request.form.get("email", "")
        pwd = request.form.get("pass", "")
        captured = f"Email: {email} | Password: {pwd}"
    return render_template_string(PHISHING_HTML, captured=captured)

@app.route("/phishing/capture", methods=["POST"])
def phishing_capture():
    return redirect("/phishing")

# ═══════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════╗
║       VulnTest Platform                     ║
║   Challenges de seguridad para Striker DAST  ║
╠══════════════════════════════════════════════╣
║  /sqli       SQL Injection (SQLite)         ║
║  /nosqli     NoSQL Injection (simulado)     ║
║  /xss/1      XSS Reflejado                  ║
║  /xss/2      XSS Almacenado                 ║
║  /cmdi       Command Injection              ║
║  /pathtrav   Path Traversal                 ║
║  /ddos       DDoS Simulation                ║
║  /phishing   Phishing Awareness             ║
╚══════════════════════════════════════════════╝
    """)
    print("  ▶ http://localhost:5005")
    app.run(host="0.0.0.0", port=5005, debug=True)
