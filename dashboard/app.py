"""
Cloud Misconfiguration Scanner - Dashboard
--------------------------------------------
A small Flask app that wraps the cloud_misconfig_scanner package (S3 + IAM
checks against Boto3-shaped JSON) in a browser dashboard.

Runs entirely against local JSON fixtures (no AWS credentials, no network
calls) so it's safe to demo publicly. Point SCANNER_FIXTURE_DIR at a
different folder, or add --profile/--region support in aws.py, to run it
against a real account instead.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from flask import Flask, jsonify, render_template, request

BASE_DIR = Path(__file__).resolve().parent
FIXTURES_DIR = BASE_DIR / "fixtures"

# Make the repo-local cloud_misconfig_scanner package importable.
sys.path.insert(0, str(BASE_DIR.parent / "src"))

from cloud_misconfig_scanner.fixtures import load_fixture_clients  # noqa: E402
from cloud_misconfig_scanner.iam import scan_iam  # noqa: E402
from cloud_misconfig_scanner.s3 import scan_s3  # noqa: E402

app = Flask(__name__)

FIXTURE_LABELS = {
    "clean-account": "Clean account (no findings expected)",
    "mixed-findings": "Mixed account (sample from README)",
    "high-risk-account": "High-risk account (many findings)",
}


def _list_fixtures() -> list[dict[str, str]]:
    fixtures = []
    for path in sorted(FIXTURES_DIR.glob("*.json")):
        key = path.stem
        fixtures.append({"id": key, "label": FIXTURE_LABELS.get(key, key)})
    return fixtures


def _run_scan(fixture_id: str) -> list[dict]:
    path = FIXTURES_DIR / f"{fixture_id}.json"
    if not path.exists():
        raise FileNotFoundError(fixture_id)

    clients = load_fixture_clients(path)
    findings = scan_s3(clients.s3, account_id=clients.account_id)
    findings.extend(scan_iam(clients.iam, account_id=clients.account_id))
    findings.sort(key=lambda f: (-f.severity.value, f.service, f.resource))
    return [f.to_dict() for f in findings]


@app.route("/")
def index():
    return render_template("index.html", fixtures=_list_fixtures())


@app.route("/api/fixtures")
def api_fixtures():
    return jsonify(_list_fixtures())


@app.route("/api/scan")
def api_scan():
    fixture_id = request.args.get("fixture", "mixed-findings")
    try:
        findings = _run_scan(fixture_id)
    except FileNotFoundError:
        return jsonify({"error": f"unknown fixture '{fixture_id}'"}), 404
    except json.JSONDecodeError as exc:
        return jsonify({"error": f"invalid fixture JSON: {exc}"}), 400

    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        summary[finding["severity"]] = summary.get(finding["severity"], 0) + 1

    return jsonify({"fixture": fixture_id, "summary": summary, "findings": findings})


if __name__ == "__main__":
    app.run(debug=False, port=5050)
