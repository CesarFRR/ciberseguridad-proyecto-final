# Striker — DAST Web Vulnerability Scanner

## Descripción

Striker es un **Dynamic Application Security Testing (DAST)** para aplicaciones web. Permite a desarrolladores seleccionar visualmente elementos de una página (inputs, botones, formularios) y escanearlos automáticamente en busca de vulnerabilidades de seguridad.

Stack: **Python 3 + Flask** (backend), **HTML/CSS/JS vanilla** (dashboard single-file). 
Sin frameworks pesados, sin dependencias de GPU, sin APIs externas obligatorias.

---

## Arquitectura

```
striker/
├── app.py                    # Entry point + create_app() factory
├── config.py                 # Configuración centralizada
├── requirements.txt          # flask, requests, python-dateutil
├── dashboard/
│   └── routes.py             # Blueprint Flask: / + /api/*
├── proxy/
│   ├── routes.py             # Blueprint: /proxy/*
│   ├── server.py             # Reverse proxy (requests al target)
│   └── injector.py           # Inyecta <script> del selector + <base> tag
├── scanner/
│   ├── engine.py             # Orquestador DAST
│   ├── attacker.py           # Construye y envía requests con payloads
│   ├── analyzer.py           # Analiza respuestas → detección de vulns
│   └── payloads/
│       ├── sqli.json         # 15 payloads SQL injection
│       ├── xss.json          # 10 payloads XSS
│       ├── nosqli.json       # 10 payloads NoSQL injection
│       ├── cmd.json          # 10 payloads command injection
│       └── mitre.json        # Mapping: MITRE ATT&CK + CWE + OWASP Top 10
├── static/
│   ├── css/style.css         # Dashboard (tema oscuro profesional)
│   └── js/
│       ├── dashboard.js      # Frontend: postMessage, tabs, sesiones
│       └── element_selector.js  # Selector visual inyectado en el target
└── templates/
    └── index.html            # Dashboard (HTML + CSS + JS inline)
```

---

## Cómo funciona

### 1. Reverse Proxy + Selector Visual
- El usuario pega una URL (ej: `http://localhost:5005/xss/1`)
- Striker actúa como reverse proxy: forwardea requests al target
- Inyecta `<base>` tag para reescribir rutas relativas
- Inyecta `element_selector.js` antes de `</body>`
- La página aparece en un iframe con el selector encima

### 2. Selector Visual (element_selector.js)
- Modo **NORMAL**: la página funciona normalmente (inputs escribibles, botones clickeables)
- Modo **SELECT** (F2 o botón): hovering azul, click selecciona
- Elementos seleccionados muestran etiquetas rojas (`T1`, `T2`)
- postMessage al dashboard con cada selección

### 3. Escáner DAST
- El usuario hace click en **SCAN**
- El dashboard envía los elementos seleccionados a `/api/targets`
- Luego dispara `/api/scan` con el session_id
- El scanner (scanner/engine.py) itera cada elemento:
  - Determina categorías de ataque según tag/type (input text → sqli, xss, nosqli)
  - Carga payloads de `scanner/payloads/*.json`
  - Construye requests con `attacker.py` (GET/POST, query params o form data)
  - Envía requests directamente al target
  - Analiza respuestas con `analyzer.py` (regex patterns, heurísticas)
- Resultados: severity, confidence, evidence, category

### 4. Clasificación Profesional
Cada vulnerabilidad se mapea contra 3 estándares:
- **MITRE ATT&CK**: T1190, T1059.007, T1005, etc.
- **CWE**: CWE-89, CWE-79, CWE-77, etc.
- **OWASP Top 10**: A01, A02, A03, A05, A07

Los datos están en `scanner/payloads/mitre.json` (3KB, offline).

---

## Endpoints API

| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/` | Dashboard |
| GET | `/proxy?target=URL` | Reverse proxy (inyecta selector) |
| POST | `/api/targets` | Registrar elementos seleccionados |
| GET | `/api/sessions` | Listar sesiones |
| POST | `/api/scan` | Disparar escaneo DAST |
| GET | `/api/scan/:id/status` | Estado + resultados del escaneo |
| DELETE | `/api/sessions/:id` | Eliminar sesión |
| DELETE | `/api/sessions/clear` | Eliminar todas las sesiones |
| GET | `/api/payloads` | Listar payloads por categoría |
| GET | `/api/mitre` | Mapping MITRE + CWE + OWASP |

---

## Payloads detectados

| Categoría | Cantidad | Ejemplo |
|-----------|----------|---------|
| SQL Injection | 15 | `' OR '1'='1`, `UNION SELECT NULL--` |
| XSS | 10 | `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>` |
| NoSQL Injection | 10 | `{"$gt":""}`, `{"$ne":null}`, `{"$where":"1==1"}` |
| Command Injection | 10 | `; ls`, `| whoami`, `` `id` `` |

---

## Indicadores de vulnerabilidad (analyzer.py)

### SQLi
- Errores de base de datos: `SQL syntax`, `mysql_fetch`, `ORA-`, `PostgreSQL ERROR`, `SQLSTATE`
- HTTP 500 con respuesta corta (posible error SQL)

### XSS
- Payload reflejado literalmente en la respuesta
- Confianza 90% si el payload aparece sin cambios

### NoSQLi
- Errores: `MongoError`, `CastError`, `BSONTypeError`
- HTTP 500 como indicio

### Command Injection
- `/etc/passwd`: `root:.*:0:0:`
- `id` output: `uid=\d+`
- `uname -a`: `Linux \S+`

---

## Flujo de datos (postMessage)

```
element_selector.js (iframe)          dashboard.js (parent)
─────────────────────────────          ─────────────────────
selection_changed {elements,count}  →  actualiza counter + UI
cmd_toggle_mode                   ←  dashboard click SELECT MODE
cmd_scan                          ←  dashboard click SCAN
scan_complete {results,count}     →  renderResults + modal
cmd_clear_selection               ←  dashboard click ✕ Clear
```

---

## UI / Dashboard

- **Activity Bar** (izquierda): iconos SVG (Scanner, Results, Payloads, Logs)
- **Tabs**: Live View, Results, Payloads, Logs
- **Nav Bar**: ← → ↻ URL bar (sobre el iframe)
- **Sidebar izq**: Target URL, Controls (SELECT MODE, SCAN, ✕ Clear), Sessions
- **Panel derecho**: Selected Elements, Scan Results
- **Modal de detalle**: click en resultado → MITRE + CWE + OWASP + remediation
- **Responsive**: hamburger menu en mobile, breakpoints 1100/850/600/400px
- **Tema**: oscuro profesional (navy/slate, sin verde hacker)

---

## Cómo ejecutar

```bash
cd striker
pip install -r requirements.txt
python app.py
# Dashboard: http://localhost:5055
# Proxy: cargar cualquier URL en el input del sidebar
```

Modo demo (sin log real):
```bash
# No aplica — el demo es el VulnTest o la app nosql-injection
```

---

## Dependencias

```
flask>=3.0
requests>=2.31
python-dateutil>=2.8
```

Sin dependencias pesadas. Sin GPU. Sin APIs externas.

---

## Relación con otros proyectos del repo

| Proyecto | Puerto | Rol |
|----------|--------|-----|
| **Interceptor** | 5000 | Monitoreo de infraestructura Docker (CPU, RAM, heartbeat) |
| **Argus** | 5050 | Detección de ataques en logs (análisis de access.log) |
| **Striker** | 5055 | DAST — escáner proactivo de vulnerabilidades web |

**Interceptor** defiende (métricas), **Argus** detecta (logs), **Striker** ataca (payloads).
La trilogía cubre el ciclo completo: defensa → detección → ofensiva.

---

## Roadmap pendiente

- [ ] **SAST / Code Analyzer**: para localhost, leer el código fuente (.py, .html) y detectar vulnerabilidades en el código mismo (sin necesidad de enviar payloads)
- [ ] **Payloads adicionales**: SSRF, XXE, deserialización insegura
- [ ] **Exportar reporte**: JSON, PDF, clipboard
- [ ] **Manejo de autenticación**: login previo para escanear apps con sesión
- [ ] **Unificar dashboard**: un solo panel con Interceptor + Argus + Striker
