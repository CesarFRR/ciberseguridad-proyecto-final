# Ciberseguridad — Proyecto Final

Plataforma de seguridad web con dos componentes:

- **Striker** — DAST Web Vulnerability Scanner (análisis dinámico de vulnerabilidades)
- **VulnTest Platform** — Aplicación de pruebas con challenges de seguridad (SQLi, XSS, NoSQLi, CMDi, Path Traversal, DDoS, Phishing)

## Proyectos

| Proyecto | Descripción | Puerto |
|----------|-------------|--------|
| `striker/` | DAST scanner con selector visual, proxy, payloads, clasificación MITRE/CWE/OWASP | 5055 |
| `pagina-testing/` | App vulnerable con 8 challenges de seguridad para testing | 5005 |

## Ejecución

```bash
# Terminal 1 — VulnTest Platform (app objetivo)
cd pagina-testing
pip install flask
python app.py

# Terminal 2 — Striker DAST Scanner
cd striker
pip install -r requirements.txt
python app.py
# Abrir http://localhost:5055
```

## Stack

Python 3 + Flask · HTML/CSS/JS vanilla · Sin dependencias pesadas · Sin GPU
