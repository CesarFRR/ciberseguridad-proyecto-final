"""scanner/crawler.py — Auto-descubrimiento de formularios e inputs vía BeautifulSoup.

Escanea una página web y encuentra todos los campos que podrían ser vulnerables.
No requiere que el dev los seleccione manualmente.
"""

import re
import urllib.parse
import requests
from bs4 import BeautifulSoup


def crawl_page(url, timeout=10):
    """
    Crawlea una URL y extrae todos los formularios e inputs.

    Args:
        url: URL completa (ej: http://localhost:5005/xss/1)
        timeout: timeout en segundos

    Returns:
        dict con:
          - forms: lista de formularios (cada uno con action, method, inputs)
          - standalone_inputs: inputs fuera de forms
          - links: links encontrados (para crawleo recursivo opcional)
    """
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True,
                           headers={"User-Agent": "Striker/1.0 DAST Crawler"})
        resp.raise_for_status()
    except Exception as e:
        return {"error": str(e), "forms": [], "standalone_inputs": [], "links": []}

    soup = BeautifulSoup(resp.text, "html.parser")
    forms = []
    standalone_inputs = []
    links = []

    # ── Forms ──────────────────────────────────────────────────
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        method = (form.get("method") or "GET").upper()
        inputs = []

        for tag in form.find_all(["input", "textarea", "select", "button"]):
            info = _extract_element_info(tag)
            if info:
                inputs.append(info)

        if inputs:
            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs,
            })

    # ── Standalone inputs (fuera de forms) ─────────────────────
    all_forms_inputs = set()
    for f in forms:
        for i in f["inputs"]:
            all_forms_inputs.add(i.get("name") or i.get("id"))

    for tag in soup.find_all(["input", "textarea"]):
        info = _extract_element_info(tag)
        if info and (info.get("name") or info.get("id")) not in all_forms_inputs:
            standalone_inputs.append(info)

    # ── Links ─────────────────────────────────────────────────
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
            links.append({"text": a.get_text(strip=True)[:60], "href": href})

    return {
        "url": url,
        "forms": forms,
        "standalone_inputs": standalone_inputs,
        "links": links,
        "total_elements": sum(len(f["inputs"]) for f in forms) + len(standalone_inputs),
    }


def crawl_to_elements(url, timeout=10):
    """
    Crawlea y devuelve los elementos en el formato que espera el scanner.
    Útil para alimentar directamente scan_element().
    """
    result = crawl_page(url, timeout)
    elements = []

    for form in result.get("forms", []):
        for inp in form.get("inputs", []):
            elements.append({
                "tag": inp.get("tag", "input"),
                "type": inp.get("type", "text"),
                "name": inp.get("name"),
                "id": inp.get("id"),
                "placeholder": inp.get("placeholder"),
                "formAction": form["action"] or _path_from_url(url),
                "formMethod": form["method"],
                "label": inp.get("label"),
                "selector": inp.get("selector"),
            })

    for inp in result.get("standalone_inputs", []):
        elements.append({
            "tag": inp.get("tag", "input"),
            "type": inp.get("type", "text"),
            "name": inp.get("name"),
            "id": inp.get("id"),
            "placeholder": inp.get("placeholder"),
            "formAction": _path_from_url(url),
            "formMethod": "GET",
            "label": inp.get("label"),
            "selector": inp.get("selector"),
        })

    return elements


def _extract_element_info(tag):
    """Extrae información de un elemento HTML."""
    if not tag:
        return None
    tagname = tag.name
    if tagname in ("input", "textarea", "select", "button"):
        name = tag.get("name")
        tid = tag.get("id")
        etype = tag.get("type", "text" if tagname == "input" else tagname)
        placeholder = tag.get("placeholder")
        # Label prioritario: name > id > placeholder > first class > tag
        cls = (tag.get("class") or [None])[0] if tag.get("class") else None
        label = name or tid or placeholder or (("." + cls) if cls else None) or tagname
        return {
            "tag": tagname,
            "type": etype,
            "name": name,
            "id": tid,
            "placeholder": placeholder,
            "label": label,
            "selector": _build_selector(tag),
        }
    return None


def _build_selector(el):
    """Construye un selector CSS único para el elemento."""
    if el.get("id"):
        return f"#{el['id']}"
    parts = []
    cur = el
    while cur and cur.name:
        sel = cur.name
        if cur.get("id"):
            parts.insert(0, f"#{cur['id']}")
            break
        cls = (cur.get("class") or [None])[0]
        if cls:
            sel += f".{cls}"
        parts.insert(0, sel)
        cur = cur.parent
    return " > ".join(parts[-4:])  # últimos 4 niveles


def _path_from_url(url):
    """Extrae el path de una URL."""
    parsed = urllib.parse.urlparse(url)
    return parsed.path or "/"
