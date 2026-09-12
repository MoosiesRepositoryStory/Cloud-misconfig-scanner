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
import json
from urllib.request import urlopen
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

import webview  # noqa: E402

from app import app as flask_app  # noqa: E402

HOST = "127.0.0.1"
PORT = 5050
SPLASH_SECONDS = 2

SPLASH_HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {
    --accent: #1b4332;
    --accent-hover: #143026;
    --accent-tint: #eef4f1;
    --bg: #fafafa;
    --text: #1f2a24;
    --muted: #6b7770;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    min-height: 100vh;
    display: grid;
    place-items: center;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, Segoe UI, Roboto, sans-serif;
  }
  .splash {
    text-align: center;
    animation: rise 420ms ease-out;
  }
  .wordmark {
    color: var(--accent);
    font-size: 2.4rem;
    font-weight: 800;
    letter-spacing: 0;
    margin: 0 0 8px;
  }
  .subtitle {
    color: var(--muted);
    font-size: 0.95rem;
    margin: 0;
  }
  .bar {
    width: 180px;
    height: 3px;
    margin: 22px auto 0;
    overflow: hidden;
    border-radius: 999px;
    background: var(--accent-tint);
  }
  .bar::after {
    content: "";
    display: block;
    width: 100%;
    height: 100%;
    background: var(--accent);
    animation: load 2s linear forwards;
    transform-origin: left center;
  }
  @keyframes rise {
    from { opacity: 0; transform: translateY(6px); }
    to { opacity: 1; transform: translateY(0); }
  }
  @keyframes load {
    from { transform: scaleX(0); }
    to { transform: scaleX(1); }
  }
</style>
</head>
<body>
  <main class="splash" aria-label="Launching Cloud Misconfiguration Scanner">
    <h1 class="wordmark">Cloud Misconfiguration Scanner</h1>
    <p class="subtitle">Preparing S3 and IAM findings dashboard</p>
    <div class="bar" aria-hidden="true"></div>
  </main>
</body>
</html>
"""


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


def smoke_test() -> int:
    server_thread = threading.Thread(target=_run_server, daemon=True)
    server_thread.start()
    _wait_for_server()

    with urlopen(f"http://{HOST}:{PORT}/api/scan?fixture=high-risk-account", timeout=10) as response:
        payload = json.loads(response.read().decode("utf-8"))

    finding_count = len(payload.get("findings", []))
    if finding_count != 13:
        print(f"Expected 13 high-risk fixture findings, got {finding_count}.")
        return 1

    with urlopen(f"http://{HOST}:{PORT}/favicon.ico", timeout=10) as response:
        favicon = response.read()

    if len(favicon) < 1000:
        print("Expected bundled favicon.ico to be served, but response was too small.")
        return 1

    print(f"Cloud Misconfiguration Scanner smoke test passed with {finding_count} findings and favicon.ico.")
    return 0


def main() -> None:
    if "--smoke-test" in sys.argv:
        raise SystemExit(smoke_test())

    server_thread = threading.Thread(target=_run_server, daemon=True)
    server_thread.start()
    _wait_for_server()

    splash_window = webview.create_window(
        "Cloud Misconfiguration Scanner",
        html=SPLASH_HTML,
        width=560,
        height=360,
        resizable=True,
    )
    dashboard_window = webview.create_window(
        "Cloud Misconfiguration Scanner",
        f"http://{HOST}:{PORT}",
        width=1280,
        height=800,
        resizable=True,
        hidden=True,
    )

    def show_dashboard() -> None:
        time.sleep(SPLASH_SECONDS)
        dashboard_window.show()
        splash_window.destroy()

    webview.start(show_dashboard)


if __name__ == "__main__":
    main()
