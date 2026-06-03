"""scanner/process_scanner.py — Encuentra el directorio del proyecto a partir de un puerto local.

Usa comandos del sistema para encontrar qué proceso escucha en un puerto
y retorna su directorio de trabajo. Útil para SAST automático en localhost.
"""

import os
import re
import subprocess


def get_process_info(port):
    """
    Encuentra el PID, comando y directorio de trabajo del proceso
    que escucha en un puerto específico.

    Args:
        port: número de puerto (int o str)

    Returns:
        dict con {pid, command, cwd, port} o None si no encuentra
    """
    port = str(port)

    # Método 1: ss + /proc
    try:
        out = subprocess.check_output(
            ["ss", "-tlnp"], stderr=subprocess.DEVNULL, timeout=5
        ).decode()
        for line in out.split("\n"):
            if f":{port}" in line:
                # Extraer PID de "pid=12345" o "users:(("python",pid=12345"
                m = re.search(r"pid=(\d+)", line)
                if m:
                    pid = m.group(1)
                    return _from_pid(pid, port)
    except Exception:
        pass

    # Método 2: lsof
    try:
        out = subprocess.check_output(
            ["lsof", "-i", f":{port}", "-t"], stderr=subprocess.DEVNULL, timeout=5
        ).decode()
        pid = out.strip().split("\n")[0]
        if pid:
            return _from_pid(pid, port)
    except Exception:
        pass

    return None


def _from_pid(pid, port):
    """Extrae información del proceso a partir de su PID."""
    info = {"pid": int(pid), "port": int(port), "command": "", "cwd": ""}

    # Leer comando desde /proc/PID/cmdline
    try:
        cmdline_path = f"/proc/{pid}/cmdline"
        if os.path.exists(cmdline_path):
            with open(cmdline_path, "rb") as f:
                raw = f.read().replace(b"\x00", b" ").decode(errors="replace").strip()
                info["command"] = raw[:200]
    except Exception:
        pass

    # Leer CWD desde /proc/PID/cwd
    try:
        cwd_link = f"/proc/{pid}/cwd"
        if os.path.exists(cwd_link):
            info["cwd"] = os.readlink(cwd_link)
    except Exception:
        pass

    return info if info["pid"] else None


def discover_project_path(url_or_port):
    """
    A partir de un puerto o URL de localhost, descubre la ruta del proyecto.

    Args:
        url_or_port: ej: 'http://localhost:5005/xss/1' o '5005' o 'localhost:5005'

    Returns:
        dict con {pid, command, cwd, port} o None
    """
    # Extraer puerto
    port = None
    if isinstance(url_or_port, str):
        # Intentar extraer de URL
        m = re.search(r":(\d{4,5})", url_or_port)
        if m:
            port = m.group(1)
        elif url_or_port.isdigit():
            port = url_or_port
    elif isinstance(url_or_port, int):
        port = str(url_or_port)

    if not port:
        return None

    return get_process_info(port)
