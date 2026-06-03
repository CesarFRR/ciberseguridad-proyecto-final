import json
"""Dashboard Blueprint: página principal + API de estado + escaneo."""
import time
import threading
from flask import Blueprint, render_template, jsonify, request, Response, stream_with_context

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

    # Extraer target real de URL del proxy
    if "/proxy?target=" in target_url:
        from urllib.parse import urlparse, parse_qs, unquote
        parsed = urlparse(target_url)
        qs = parse_qs(parsed.query)
        real_target = qs.get("target", [None])[0]
        if real_target:
            target_url = unquote(real_target)

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
    cats = ["sqli", "xss", "nosqli", "cmd", "ssrf", "xxe"]
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


@dashboard_bp.route("/api/attacks", methods=["GET"])
def api_attacks():
    """Devuelve la base de datos de ataques con descripciones y remediación."""
    from scanner.engine import PAYLOADS_DIR
    path = PAYLOADS_DIR / "attacks.json"
    if not path.exists():
        return jsonify({"error": "not found"}), 404
    with open(path) as f:
        return jsonify(json.load(f))


# ═══════════════════════════════════════════════════════════════════
#  DDoS SIMULATION
# ═══════════════════════════════════════════════════════════════════

@dashboard_bp.route("/api/ddos/start", methods=["POST"])
def api_ddos_start():
    """Inicia simulación DDoS."""
    from scanner.ddos import ddos_engine
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url", "")
    threads = int(data.get("threads", 10))
    duration = int(data.get("duration", 10))

    if not url:
        return jsonify({"error": "url required"}), 400

    result = ddos_engine.start(url, threads=threads, duration=duration)
    return jsonify(result)


@dashboard_bp.route("/api/ddos/stop", methods=["POST"])
def api_ddos_stop():
    """Detiene simulación DDoS."""
    from scanner.ddos import ddos_engine
    ddos_engine.stop()
    return jsonify({"status": "stopped"})


@dashboard_bp.route("/api/ddos/stats")
def api_ddos_stats():
    """Estadísticas del DDoS en curso."""
    from scanner.ddos import ddos_engine
    return jsonify(ddos_engine.get_stats())


# ═══════════════════════════════════════════════════════════════════
#  SENSORES (live attack monitoring)
# ═══════════════════════════════════════════════════════════════════

@dashboard_bp.route("/api/sensors")
def api_sensors():
    """Estado actual de los sensores."""
    from scanner.sensors import sensor_engine
    return jsonify(sensor_engine.get_summary())


@dashboard_bp.route("/api/sensors/stream")
def api_sensors_stream():
    """SSE stream de alertas de sensores en tiempo real."""
    from scanner.sensors import sensor_engine

    def generate():
        last_id = 0
        while True:
            recent = sensor_engine.get_recent(20)
            new_alerts = [a for a in recent if a["id"] > last_id]
            if new_alerts:
                last_id = new_alerts[0]["id"]
                yield f"data: {json.dumps({'alerts': new_alerts, 'summary': sensor_engine.get_summary()})}\n\n"
            time.sleep(1.0)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ═══════════════════════════════════════════════════════════════════
#  CRAWLER + SAST
# ═══════════════════════════════════════════════════════════════════

@dashboard_bp.route("/api/crawl", methods=["POST"])
def api_crawl():
    """Crawlea una URL y descubre formularios/inputs automáticamente."""
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url", "")

    if not url:
        return jsonify({"error": "url required"}), 400

    from scanner.crawler import crawl_to_elements
    elements = crawl_to_elements(url)

    return jsonify({
        "url": url,
        "elements": elements,
        "count": len(elements),
    })


@dashboard_bp.route("/api/sast", methods=["POST"])
def api_sast():
    """Escanea un directorio con SAST (análisis estático Python)."""
    data = request.get_json(force=True, silent=True) or {}
    dirpath = data.get("path", "")

    if not dirpath:
        return jsonify({"error": "path required"}), 400

    from scanner.python_sast import scan_directory
    findings = scan_directory(dirpath)

    return jsonify({
        "path": dirpath,
        "findings": findings,
        "count": len(findings),
    })
