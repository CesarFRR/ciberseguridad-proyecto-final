"""Striker config: puerto, modos, umbrales."""
import os

PORT = int(os.environ.get("PORT", 5055))
DEBUG = os.environ.get("DEBUG", "1") == "1"
DEMO_MODE = os.environ.get("DEMO", "0") == "1"

# ── Scanner ──────────────────────────────────────────────────────
SCAN_TIMEOUT = 15         # segundos por request
MAX_PAYLOADS_PER_FIELD = 5  # cuántos payloads probar por campo
USER_AGENT = "Striker/1.0 (DAST Scanner)"

# ── Proxy ────────────────────────────────────────────────────────
STRIP_HEADERS = {
    "x-frame-options", "content-security-policy",
    "x-content-security-policy", "x-webkit-csp",
}
SKIP_HEADERS = {
    "host", "connection", "accept-encoding",
    "content-length", "transfer-encoding",
}
