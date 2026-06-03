"""Proxy server: forwardea requests al target, inyecta el selector."""
import requests
from flask import Response, request as flask_request

import config
from proxy.injector import get_upstream_url, should_inject, inject_script
from scanner.sensors import sensor_engine


def proxy_request(target_url, path):
    full_url = target_url + path
    fwd_headers = {}
    for k, v in flask_request.headers:
        if k.lower() not in config.SKIP_HEADERS:
            fwd_headers[k] = v
    if "X-Forwarded-For" not in fwd_headers:
        fwd_headers["X-Forwarded-For"] = flask_request.remote_addr

    try:
        upstream = requests.request(
            method=flask_request.method, url=full_url,
            headers=fwd_headers, data=flask_request.get_data(),
            allow_redirects=False, timeout=config.SCAN_TIMEOUT, stream=False,
        )
    except requests.exceptions.ConnectionError:
        return Response("Error: no se pudo conectar al target", status=502)
    except requests.exceptions.Timeout:
        return Response("Error: timeout", status=504)
    except Exception as e:
        return Response(f"Error: {e}", status=502)

    resp_headers = {}
    resp_skip = {"content-encoding", "transfer-encoding", "content-length",
                  "connection", "keep-alive"}
    for k, v in upstream.headers.items():
        key_lower = k.lower()
        if key_lower not in resp_skip and key_lower not in config.STRIP_HEADERS:
            resp_headers[k] = v

    content = upstream.content
    if should_inject(upstream.headers.get("Content-Type", "")):
        content = inject_script(content, target_url)
        resp_headers["Content-Length"] = str(len(content))

    # ── Sensor: escanear tráfico ─────────────────────────────
    try:
        req_body = flask_request.get_data(as_text=True) if flask_request.method in ("POST", "PUT") else ""
        resp_text = upstream.text if len(upstream.text) < 50000 else upstream.text[:50000]
        sensor_engine.scan(
            ip=flask_request.remote_addr,
            method=flask_request.method,
            url=path,
            status=upstream.status_code,
            req_body=req_body,
            resp_body=resp_text,
        )
    except Exception:
        pass  # sensor nunca debe romper el proxy

    return Response(content, status=upstream.status_code, headers=resp_headers)
