"""
Cloud Misconfiguration Scanner - Desktop App
----------------------------------------------
Wraps the Flask dashboard (app.py) in a native PyWebView window so it can be
launched as a standalone desktop app instead of requiring a browser.

app.py itself is untouched and still works standalone (`python dashboard/app.py`)
for browser mode.
"""

from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

import webview  # noqa: E402

from app import app as flask_app  # noqa: E402

HOST = "127.0.0.1"
PORT = 5050


def _run_server() -> None:
    # debug=False (and use_reloader=False) is required here: Flask's reloader
    # spawns a second subprocess that re-imports this module, which on
    # Windows tries to start a second native webview window and start()
    # a second Flask server on the same port.
    flask_app.run(host=HOST, port=PORT, debug=False, use_reloader=False)


def _wait_for_server(timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, PORT), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"Flask server did not start on {HOST}:{PORT} within {timeout}s")


def main() -> None:
    server_thread = threading.Thread(target=_run_server, daemon=True)
    server_thread.start()
    _wait_for_server()

    webview.create_window(
        "Cloud Misconfiguration Scanner",
        f"http://{HOST}:{PORT}",
        width=1280,
        height=800,
        resizable=True,
    )
    webview.start()


if __name__ == "__main__":
    main()
