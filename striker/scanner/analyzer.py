"""scanner/analyzer.py — Detecta vulnerabilidades en respuestas HTTP."""
import re

# ── Indicadores de SQL Injection ─────────────────────────────────
SQLI_ERRORS = [
    r"(?i)(SQL syntax.*MySQL)",
    r"(?i)(Warning.*mysql_)",
    r"(?i)(MySQLSyntaxErrorException)",
    r"(?i)(valid MySQL result)",
    r"(?i)(PostgreSQL.*ERROR)",
    r"(?i)(SQLite.*error)",
    r"(?i)(ORA-\d{5})",
    r"(?i)(Microsoft SQL Server)",
    r"(?i)(ODBC.*Driver)",
    r"(?i)(SQLSTATE\[\d+\])",
    r"(?i)(DB2 SQL Error)",
    r"(?i)(JDBC.*error)",
    r"(?i)(org\.hibernate\.exception)",
    r"(?i)(unclosed quotation mark)",
    r"(?i)(Unclosed quotation mark)",
    r"(?i)(syntax error.*near)",
    r"(?i)(You have an error in your SQL)",
    r"(?i)(Incorrect syntax near)",
]

# ── Indicadores de NoSQL Injection ───────────────────────────────
NOSQLI_INDICATORS = [
    r"(?i)(MongoError)",
    r"(?i)(MongoServerError)",
    r"(?i)(\$gt|\$ne|\$regex) is not allowed",
    r"(?i)(CastError|BSONTypeError)",
    r"(?i)(MongooseError)",
    r"(?i)(MongoNetworkError)",
]

# ── Indicadores de Command Injection ─────────────────────────────
CMDI_INDICATORS = [
    r"root:.*:0:0:",                          # /etc/passwd
    r"(?i)(uid=\d+\(.*\)\s+gid=\d+)",        # output de id
    r"(?i)(Linux\s+\S+\s+\d+\.\d+)",          # uname -a
    r"(?i)(Microsoft Windows.*Version)",       # dir en Windows
    r"(?i)(Volume.*Serial.*Number)",           # dir en Windows
]

# ── Indicadores de Path Traversal ────────────────────────────────
PATHTRAV_INDICATORS = [
    r"root:.*:0:0:",                           # /etc/passwd
    r"\[boot loader\]",                        # boot.ini
    r"\[fonts\]",                              # win.ini
]


def analyze(payload, response, category):
    """
    Analiza una respuesta HTTP para determinar si la inyección fue exitosa.

    Args:
        payload: dict con id, value, severity
        response: dict con status_code, text, headers, elapsed
        category: str — 'sqli', 'xss', 'nosqli', 'cmd', 'pathtrav'

    Returns:
        dict con vulnerable (bool), confidence (0-100), evidence (str),
        severity (str), category (str)
        o None si no se detectó vulnerabilidad
    """
    if response.get("error"):
        return None

    text = response.get("text", "")
    status = response.get("status_code", 0)
    payload_value = payload.get("value", "")
    severity = payload.get("severity", "medium")

    result = None

    if category == "sqli":
        result = _check_sqli(text, status)
    elif category == "xss":
        result = _check_xss(text, payload_value)
    elif category == "nosqli":
        result = _check_nosqli(text, status)
    elif category == "cmd":
        result = _check_cmdi(text)
    elif category == "pathtrav":
        result = _check_pathtrav(text)

    # Ajustes comunes: respuesta 500 con error es fuerte indicio
    if result and result.get("vulnerable") and status >= 500:
        result["confidence"] = min(100, result["confidence"] + 20)

    # Si el request redirigió a login (status 302 a /login), posible bypass
    if category in ("sqli", "nosqli") and status == 302:
        location = response.get("headers", {}).get("Location", "")
        if "login" not in location.lower():
            result = result or {}
            result["vulnerable"] = True
            result["confidence"] = 70
            result["evidence"] = f"Redirigido a {location} — posible bypass de auth"
            result["severity"] = "critical"
            result["category"] = category

    # Inyectar severity del payload
    if result and result.get("vulnerable"):
        result.setdefault("severity", severity)
        result.setdefault("category", category)

    return result


def _check_sqli(text, status):
    """Detecta SQL injection en la respuesta."""
    for pattern in SQLI_ERRORS:
        match = re.search(pattern, text)
        if match:
            return {
                "vulnerable": True,
                "confidence": 85,
                "evidence": match.group(0)[:200],
                "category": "sqli",
            }
    if status >= 500 and len(text) < 100:
        return {
            "vulnerable": True,
            "confidence": 50,
            "evidence": f"HTTP {status} con respuesta mínima — posible error SQL",
            "category": "sqli",
        }
    return None


def _check_xss(text, payload_value):
    """Detecta XSS: el payload se refleja sin sanitizar."""
    escaped_value = re.escape(payload_value)
    if re.search(escaped_value, text, re.IGNORECASE):
        return {
            "vulnerable": True,
            "confidence": 90,
            "evidence": f"Payload reflejado en la respuesta: {payload_value[:80]}",
            "category": "xss",
        }
    return None


def _check_nosqli(text, status):
    """Detecta NoSQL injection (MongoDB, etc)."""
    for pattern in NOSQLI_INDICATORS:
        match = re.search(pattern, text)
        if match:
            return {
                "vulnerable": True,
                "confidence": 80,
                "evidence": match.group(0)[:200],
                "category": "nosqli",
            }
    if status >= 500:
        return {
            "vulnerable": True,
            "confidence": 40,
            "evidence": f"HTTP {status} — posible error NoSQL",
            "category": "nosqli",
        }
    return None


def _check_cmdi(text):
    """Detecta command injection: output de comandos del sistema."""
    for pattern in CMDI_INDICATORS:
        match = re.search(pattern, text)
        if match:
            return {
                "vulnerable": True,
                "confidence": 95,
                "evidence": match.group(0)[:200],
                "category": "cmdi",
            }
    return None


def _check_pathtrav(text):
    """Detecta path traversal exitoso."""
    for pattern in PATHTRAV_INDICATORS:
        match = re.search(pattern, text)
        if match:
            return {
                "vulnerable": True,
                "confidence": 95,
                "evidence": match.group(0)[:200],
                "category": "pathtrav",
            }
    return None
