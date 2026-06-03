"""scanner/attacker.py — Construye y envía requests con payloads inyectados."""
import json
import urllib.parse
from copy import deepcopy

import requests
import config


def build_request(target_url, element_info, payload):
    """
    Construye un request con el payload inyectado según el tipo de elemento.

    Args:
        target_url: URL base del target (ej: http://localhost:5000)
        element_info: dict con tag, name, type, formAction, formMethod, selector
        payload: dict con id, value, method (replace|append)

    Returns:
        dict con method, url, headers, data/params listo para enviar
    """
    tag = element_info.get("tag", "").lower()
    etype = element_info.get("type", "")
    name = element_info.get("name") or element_info.get("id") or "field"
    value = payload.get("value", "")
    method = payload.get("method", "replace")
    form_action = element_info.get("formAction") or "/"
    form_method = (element_info.get("formMethod") or "GET").upper()

    # Construir URL del endpoint
    if form_action.startswith("http"):
        endpoint = form_action
    else:
        if not form_action.startswith("/"):
            form_action = "/" + form_action
        endpoint = target_url.rstrip("/") + form_action

    # Calcular el valor a inyectar
    injected_value = _build_injected_value(element_info, value, method)

    # Construir request según método y tipo de elemento
    if etype in ("text", "email", "search", "", None) or tag in ("textarea",):
        if form_method == "POST":
            return {
                "method": "POST",
                "url": endpoint,
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "data": urllib.parse.urlencode({name: injected_value}),
            }
        else:
            parsed = urllib.parse.urlparse(endpoint)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            qs[name] = [injected_value]
            new_qs = urllib.parse.urlencode(qs, doseq=True)
            new_url = parsed._replace(query=new_qs).geturl()
            return {"method": "GET", "url": new_url, "headers": {}, "params": None}

    elif etype == "password":
        # Para passwords, suele ir en POST con el form
        return {
            "method": "POST",
            "url": endpoint,
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "data": urllib.parse.urlencode({name: injected_value}),
        }

    elif tag == "a":
        # Links: inyectar en query params
        return {"method": "GET", "url": endpoint, "headers": {}, "params": {name: injected_value}}

    # Default: GET con query param
    return {"method": "GET", "url": endpoint, "headers": {}, "params": {name: injected_value}}


def send_request(req_info):
    """
    Envía un request preparado y retorna la respuesta parseada.

    Returns:
        dict con status_code, text, headers, elapsed
    """
    method = req_info.get("method", "GET")
    url = req_info["url"]
    headers = dict(req_info.get("headers", {}))
    headers.setdefault("User-Agent", config.USER_AGENT)

    kwargs = {
        "method": method,
        "url": url,
        "headers": headers,
        "timeout": config.SCAN_TIMEOUT,
        "allow_redirects": True,
        "verify": False,  # para localhost sin SSL
    }

    data = req_info.get("data")
    params = req_info.get("params")

    if data:
        kwargs["data"] = data
    if params:
        kwargs["params"] = params

    try:
        resp = requests.request(**kwargs)
        return {
            "status_code": resp.status_code,
            "text": resp.text,
            "headers": dict(resp.headers),
            "elapsed": resp.elapsed.total_seconds(),
            "url": resp.url,
        }
    except Exception as e:
        return {"error": str(e), "status_code": 0, "text": "", "headers": {}, "elapsed": 0}


def _build_injected_value(element_info, payload_value, method):
    """Construye el valor a inyectar según el método (replace, append)."""
    placeholder = element_info.get("placeholder", "")
    existing = element_info.get("value", "")

    if method == "append":
        base = existing or placeholder or ""
        return base + payload_value
    else:
        # replace: usar el payload directamente
        return payload_value
