"""Proxy Blueprint: reverse proxy + element selector injection."""
from flask import Blueprint, Response, request

import config
from proxy.server import proxy_request
from proxy.injector import get_upstream_url

proxy_bp = Blueprint("proxy", __name__)


@proxy_bp.route("/proxy")
def proxy():
    target = get_upstream_url()
    if not target:
        return "Error: falta ?target=http://...", 400
    path = request.args.get("path", "/")
    if not path.startswith("/"):
        path = "/" + path
    return proxy_request(target, path)


@proxy_bp.route("/proxy/<path:catchall>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def proxy_catchall(catchall):
    target = get_upstream_url()
    if not target:
        return "Error: falta target", 400
    path = "/" + catchall
    if request.query_string:
        path += "?" + request.query_string.decode()
    return proxy_request(target, path)
