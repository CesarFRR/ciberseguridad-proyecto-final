"""Dashboard Blueprint: página principal + API de estado + escaneo."""
import time
import threading
from flask import Blueprint, render_template, jsonify, request

import config
from scanner.engine import scan_session as run_scan

dashboard_bp = Blueprint("dashboard", __name__)

# ── Estado compartido ──────────────────────────────────────────────
scan_sessions = {}
session_counter = 0
scan_lock = threading.Lock()


@dashboard_bp.route("/")
def index():
    return render_template("index.html", port=config.PORT)


@dashboard_bp.route("/api/targets", methods=["POST"])
def api_targets():
    global session_counter
    data = request.get_json(force=True, silent=True) or {}
    elements = data.get("elements", [])
    target_url = request.args.get("target", "unknown")

    session_counter += 1
    session_id = f"session_{int(time.time())}_{session_counter}"

    scan_sessions[session_id] = {
        "id": session_id,
        "elements": elements,
        "count": len(elements),
        "timestamp": time.time(),
        "target_url": target_url,
        "scan_status": "registered",
        "results": [],
    }
    return jsonify({"status": "ok", "count": len(elements), "session_id": session_id})


@dashboard_bp.route("/api/sessions", methods=["GET"])
def api_sessions():
    sessions = [
        {
            "id": s["id"],
            "count": s["count"],
            "timestamp": s["timestamp"],
            "target_url": s.get("target_url", ""),
            "scan_status": s.get("scan_status", "registered"),
            "result_count": len(s.get("results", [])),
        }
        for s in scan_sessions.values()
    ]
    return jsonify({"sessions": sessions})


@dashboard_bp.route("/api/scan", methods=["POST"])
def api_scan():
    """Dispara un escaneo DAST sobre los elementos de una sesión."""
    data = request.get_json(force=True, silent=True) or {}
    session_id = data.get("session_id", "")

    if not session_id or session_id not in scan_sessions:
        return jsonify({"status": "error", "message": "Sesión no encontrada"}), 404

    session = scan_sessions[session_id]

    if session.get("scan_status") == "scanning":
        return jsonify({"status": "error", "message": "Escaneo ya en progreso"}), 409

    session["scan_status"] = "scanning"

    def _run():
        with scan_lock:
            try:
                results = run_scan(session)
                session["results"] = results
                session["scan_status"] = "done"
            except Exception as e:
                session["scan_status"] = "error"
                session["results"] = [{"error": str(e)}]

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    return jsonify({
        "status": "scanning",
        "session_id": session_id,
        "element_count": session["count"],
    })


@dashboard_bp.route("/api/scan/<session_id>/status", methods=["GET"])
def api_scan_status(session_id):
    """Consulta el estado de un escaneo."""
    if session_id not in scan_sessions:
        return jsonify({"status": "error", "message": "Sesión no encontrada"}), 404

    session = scan_sessions[session_id]
    return jsonify({
        "session_id": session_id,
        "scan_status": session.get("scan_status", "registered"),
        "result_count": len(session.get("results", [])),
        "results": session.get("results", []),
    })


@dashboard_bp.route("/api/sessions/<session_id>", methods=["DELETE"])
def api_delete_session(session_id):
    """Elimina una sesión."""
    if session_id in scan_sessions:
        del scan_sessions[session_id]
        return jsonify({"status": "ok"})
    return jsonify({"status": "error", "message": "Sesión no encontrada"}), 404


@dashboard_bp.route("/api/sessions/clear", methods=["DELETE"])
def api_clear_sessions():
    """Elimina todas las sesiones."""
    count = len(scan_sessions)
    scan_sessions.clear()
    return jsonify({"status": "ok", "deleted": count})


@dashboard_bp.route("/api/payloads", methods=["GET"])
def api_payloads():
    """Devuelve todos los payloads agrupados por categoría."""
    from scanner.engine import load_payloads
    cats = ["sqli", "xss", "nosqli", "cmd"]
    result = {}
    for c in cats:
        result[c] = load_payloads(c)
    return jsonify({"payloads": result})


@dashboard_bp.route("/api/mitre", methods=["GET"])
def api_mitre():
    """Devuelve el mapping MITRE ATT&CK + CWE + OWASP."""
    from scanner.engine import PAYLOADS_DIR
    import json
    path = PAYLOADS_DIR / "mitre.json"
    if not path.exists():
        return jsonify({"error": "not found"}), 404
    with open(path) as f:
        return jsonify(json.load(f))
