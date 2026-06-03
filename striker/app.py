#!/usr/bin/env python3
"""Striker DAST — Entry point."""
from flask import Flask

import config


def create_app():
    app = Flask(__name__)

    from dashboard.routes import dashboard_bp
    from proxy.routes import proxy_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(proxy_bp)

    @app.route("/__striker__/element_selector.js")
    def serve_selector():
        from flask import make_response
        resp = make_response(app.send_static_file("js/element_selector.js"))
        resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return resp

    return app


if __name__ == "__main__":
    print(r"""
    ╔══════════════════════════════════════════╗
    ║       S T R I K E R  -  DAST            ║
    ║    Phase 1 · Proxy + Element Selector    ║
    ╚══════════════════════════════════════════╝
    """)
    print(f"  ◈ Dashboard:  http://localhost:{config.PORT}")
    print(f"  ◈ Proxy:      /proxy?target=http://TU_APP")
    print()

    app = create_app()
    app.run(host="0.0.0.0", port=config.PORT, debug=config.DEBUG, threaded=True)
