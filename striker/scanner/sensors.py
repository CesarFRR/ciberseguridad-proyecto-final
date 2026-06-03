"""scanner/sensors.py — Motor de sensores de ataque en tiempo real.

Observa tráfico HTTP (requests + responses) y detecta patrones
de ataque usando firmas regex. Emite alertas al dashboard vía SSE.
"""

import re
import time
import threading
from collections import deque

# ── Firmas de ataque ─────────────────────────────────────────────
SIGNATURES = [
    # SQL Injection
    (r"(?i)(\bUNION\s+SELECT\b)", "SQL Injection", "critical", "T1190"),
    (r"(?i)(\bOR\s+['\"]?\d['\"]?\s*=\s*['\"]?\d['\"]?)", "SQL Injection", "critical", "T1190"),
    (r"(?i)(--\s*$|#\s*$|\/\*.*\*\/)", "SQL Injection", "high", "T1190"),
    (r"(?i)(\bSELECT\b.+\bFROM\b)", "SQL Injection", "high", "T1190"),
    (r"(?i)(\bSLEEP\s*\(|\bBENCHMARK\s*\()", "SQL Injection", "high", "T1190"),
    (r"(?i)(\bINFORMATION_SCHEMA\b)", "SQL Injection", "medium", "T1190"),

    # NoSQL Injection
    (r'(?i)(\$gt|\$ne|\$gte|\$lte|\$where|\$regex)', "NoSQL Injection", "critical", "T1190"),
    (r'(?i)(\{\s*"\$gt"|\[\s*"\$ne")', "NoSQL Injection", "high", "T1190"),

    # XSS
    (r"(?i)(<script[^>]*>)", "Cross-Site Scripting", "high", "T1059.007"),
    (r"(?i)(javascript\s*:)", "Cross-Site Scripting", "high", "T1059.007"),
    (r"(?i)(onerror\s*=|onload\s*=|onclick\s*)", "Cross-Site Scripting", "high", "T1059.007"),
    (r'(?i)(<img[^>]+onerror\s*=)', "Cross-Site Scripting", "high", "T1059.007"),
    (r'(?i)(<svg[^>]+onload\s*=)', "Cross-Site Scripting", "high", "T1059.007"),

    # Command Injection
    (r"(?i)(;\s*(?:ls|cat|id|whoami|uname|wget|curl)\b)", "Command Injection", "critical", "T1059.004"),
    (r"(?i)(\|\s*(?:ls|cat|id|whoami|nc)\b)", "Command Injection", "critical", "T1059.004"),
    (r"(?i)(\b(?:bash|sh|cmd|powershell)\s+-c\b)", "Command Injection", "critical", "T1059.004"),
    (r"(`[^`]+`)", "Command Injection", "high", "T1059.004"),

    # Path Traversal
    (r"(\.\./|\.\.\\)", "Path Traversal", "high", "T1005"),
    (r"(/etc/passwd|/etc/shadow|/etc/hosts)", "Path Traversal", "high", "T1005"),
    (r"(%2e%2e/|%2e%2e%5c)", "Path Traversal", "medium", "T1005"),

    # File Inclusion
    (r"(?i)((?:file|include|page|path)\s*=\s*(?:https?://|ftp://))", "File Inclusion", "high", "T1190"),
    (r"(?i)(php://filter|php://input|data://text)", "File Inclusion", "high", "T1190"),

    # Scanner / Recon
    (r"(?i)(nmap|nikto|sqlmap|nessus|zgrab|gobuster|dirbuster)", "Scanner Recon", "medium", "T1595"),
    (r"(?i)(\.(?:git|svn)/HEAD|\.env|\.aws/credentials)", "Scanner Recon", "medium", "T1595"),
    (r"(?i)(wp-admin|wp-login|phpmyadmin|phpinfo)", "Scanner Recon", "medium", "T1595"),

    # DDoS / High rate
    # (detectado por rate, no por regex — ver check_rate())
]

# ── Sensor Engine ────────────────────────────────────────────────
class SensorEngine:
    def __init__(self, max_alerts=200):
        self.alerts = deque(maxlen=max_alerts)
        self.alert_id = 0
        self.lock = threading.Lock()
        self._rate_tracker = {}  # IP → [timestamps]

    def scan(self, ip, method, url, status, req_body, resp_body):
        """Escanea un request/response y emite alertas si detecta ataques."""
        target = f"{url} {req_body or ''} {resp_body or ''}"
        found = []

        for pattern, atype, severity, mitre in SIGNATURES:
            match = re.search(pattern, target)
            if match:
                found.append({
                    "type": atype,
                    "severity": severity,
                    "mitre": mitre,
                    "matched": match.group(0)[:80],
                    "source": "url" if match.group(0) in (url or "") else "body",
                })

        # Rate-based DDoS detection
        rate_alert = self._check_rate(ip)
        if rate_alert:
            found.append(rate_alert)

        if found:
            with self.lock:
                self.alert_id += 1
                alert = {
                    "id": self.alert_id,
                    "time": time.time(),
                    "ip": ip,
                    "method": method,
                    "url": (url or "")[:120],
                    "status": status,
                    "findings": found,
                }
                self.alerts.appendleft(alert)

        return found

    def _check_rate(self, ip):
        """Detecta posible DDoS por tasa de requests."""
        now = time.time()
        with self.lock:
            if ip not in self._rate_tracker:
                self._rate_tracker[ip] = []
            times = self._rate_tracker[ip]
            times.append(now)
            # Mantener solo últimos 10 segundos
            times[:] = [t for t in times if now - t < 10]
            if len(times) > 50:  # más de 50 requests en 10s
                return {
                    "type": "DDoS / High Rate",
                    "severity": "critical",
                    "mitre": "T1498",
                    "matched": f"{len(times)} requests in 10s",
                    "source": "rate",
                }
        return None

    def get_recent(self, limit=30):
        """Retorna las últimas alertas."""
        with self.lock:
            return list(self.alerts)[:limit]

    def get_summary(self):
        """Resumen de actividad."""
        with self.lock:
            recent = list(self.alerts)[:100]
            types = {}
            sevs = {}
            ips = set()
            for a in recent:
                for f in a["findings"]:
                    types[f["type"]] = types.get(f["type"], 0) + 1
                    sevs[f["severity"]] = sevs.get(f["severity"], 0) + 1
                ips.add(a["ip"])
            return {
                "total_alerts": len(recent),
                "unique_ips": len(ips),
                "by_type": types,
                "by_severity": sevs,
                "recent": recent[:10],
            }


# ── Instancia global ──────────────────────────────────────────────
sensor_engine = SensorEngine()
