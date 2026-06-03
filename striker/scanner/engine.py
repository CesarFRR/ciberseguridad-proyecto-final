"""scanner/engine.py — Orquestador DAST. Conecta attacker + analyzer."""
import json
import time
from pathlib import Path

from scanner.attacker import build_request, send_request
from scanner.analyzer import analyze

PAYLOADS_DIR = Path(__file__).parent / "payloads"

# ── Payload loading ───────────────────────────────────────────────
def load_payloads(category):
    path = PAYLOADS_DIR / f"{category}.json"
    if not path.exists():
        return []
    with open(path) as f:
        return json.load(f).get("payloads", [])


# ── Category mapping ──────────────────────────────────────────────
def _categories_for_element(tag, etype, info):
    cats = []
    tag = tag.lower()
    if tag in ("input", "textarea"):
        if etype in ("text", "email", "search", "url", "", None):
            cats.extend(["sqli", "xss", "nosqli", "ssrf"])
        elif etype == "password":
            cats.extend(["sqli", "nosqli"])
    elif tag == "select":
        cats.append("sqli")
    elif tag in ("a", "button"):
        cats.extend(["xss", "sqli"])
    if info.get("formAction"):
        cats.append("sqli")
        cats.append("ssrf")
    return list(set(cats))


# ── Single element scan ───────────────────────────────────────────
def scan_element(element_info, target_url, max_payloads=5):
    """
    Escanea UN elemento con payloads relevantes.

    Args:
        element_info: dict con tag, name, id, type, formAction, selector
        target_url:  URL base del target
        max_payloads: cuántos payloads probar por categoría

    Returns:
        list de hallazgos [{type, severity, confidence, evidence, payload, element}]
    """
    findings = []
    tag = element_info.get("tag", "")
    etype = element_info.get("type", "")
    categories = _categories_for_element(tag, etype, element_info)

    for cat in categories:
        payloads = load_payloads(cat)
        for p in payloads[:max_payloads]:
            try:
                # 1. Construir request con payload
                req_info = build_request(target_url, element_info, p)

                # 2. Enviar
                response = send_request(req_info)

                if response.get("error"):
                    continue

                # 3. Analizar respuesta
                result = analyze(p, response, cat)

                if result and result.get("vulnerable"):
                    result["element"] = (
                        element_info.get("name")
                        or element_info.get("id")
                        or element_info.get("selector", "?")
                    )
                    result["tag"] = tag
                    result["payload_id"] = p.get("id", "?")
                    result["payload_value"] = p.get("value", "")
                    result["status_code"] = response.get("status_code", 0)
                    result["elapsed"] = response.get("elapsed", 0)
                    findings.append(result)

                    # Break: ya encontramos vulnerabilidad en esta categoría
                    break

            except Exception as e:
                continue  # skip payloads que fallan

    return findings


# ── Session scan ──────────────────────────────────────────────────
def scan_session(session_data, progress_callback=None):
    """
    Escanea TODOS los elementos de una sesión.

    Args:
        session_data: dict con {elements, target_url}
        progress_callback: fn(current, total) opcional

    Returns:
        list de todos los hallazgos
    """
    elements = session_data.get("elements", [])
    target = session_data.get("target_url", "")
    all_findings = []
    total = len(elements)

    for idx, elem in enumerate(elements):
        if progress_callback:
            progress_callback(idx + 1, total)

        findings = scan_element(elem, target)
        for f in findings:
            f["element_idx"] = idx
            f["element_selector"] = elem.get("selector", "")
            f["session_target"] = target
        all_findings.extend(findings)

    return all_findings
