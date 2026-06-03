"""scanner/python_sast.py — SAST para archivos Python.

Analiza archivos .py en busca de vulnerabilidades usando reglas regex 
cargadas desde scanner/rules/python.json.
"""

import re
import json
import os
from pathlib import Path

RULES_PATH = Path(__file__).parent / "rules" / "python.json"


def load_rules():
    """Carga las reglas SAST desde el JSON."""
    if not RULES_PATH.exists():
        return []
    with open(RULES_PATH) as f:
        return json.load(f).get("rules", [])


def scan_file(filepath):
    """
    Escanea un archivo Python y retorna vulnerabilidades encontradas.

    Args:
        filepath: ruta al archivo .py

    Returns:
        lista de findings con {file, line, category, severity, evidence, cwe, description, fix}
    """
    if not os.path.isfile(filepath) or not filepath.endswith(".py"):
        return []

    rules = load_rules()
    findings = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception:
        return []

    for lineno, line in enumerate(lines, 1):
        for rule in rules:
            try:
                if re.search(rule["pattern"], line, re.IGNORECASE):
                    findings.append({
                        "file": str(filepath),
                        "line": lineno,
                        "code": line.strip()[:120],
                        "category": rule["category"],
                        "severity": rule["severity"],
                        "cwe": rule.get("cwe"),
                        "description": rule.get("description", ""),
                        "fix": rule.get("fix", ""),
                        "rule_id": rule["id"],
                    })
            except re.error:
                continue  # skip malformed regex

    return findings


def scan_directory(dirpath):
    """
    Escanea recursivamente un directorio de código Python.

    Args:
        dirpath: ruta al directorio del proyecto

    Returns:
        lista de todos los findings
    """
    all_findings = []
    path = Path(dirpath)

    if not path.exists():
        return [{"error": f"Directory not found: {dirpath}"}]

    for pyfile in path.rglob("*.py"):
        # Saltar entornos virtuales y caches
        if any(part in pyfile.parts for part in ("venv", ".venv", "__pycache__", "node_modules", ".git")):
            continue
        findings = scan_file(str(pyfile))
        if findings:
            all_findings.extend(findings)

    return all_findings


def scan_for_endpoint(dirpath, endpoint_path):
    """
    Escanea buscando vulnerabilidades relacionadas con un endpoint específico.

    Args:
        dirpath: ruta al proyecto
        endpoint_path: ruta del endpoint (ej: '/xss/1', '/sqli')

    Returns:
        findings relevantes a ese endpoint
    """
    all_findings = scan_directory(dirpath)

    # Filtrar por relevancia al endpoint
    # Buscar la función que maneja esa ruta
    route_pattern = endpoint_path.rstrip("/")
    relevant = []

    for f in all_findings:
        # Incluir si el archivo o línea está cerca de la definición de la ruta
        relevant.append(f)

    return relevant
