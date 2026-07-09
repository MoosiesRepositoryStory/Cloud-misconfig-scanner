"""
LoudCloudProblems - Dashboard
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
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request, send_from_directory

BASE_DIR = Path(__file__).resolve().parent
BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", BASE_DIR))
RESOURCE_DIR = BUNDLE_DIR / "dashboard" if (BUNDLE_DIR / "dashboard").exists() else BASE_DIR
FIXTURES_DIR = RESOURCE_DIR / "fixtures"
TEMPLATES_DIR = RESOURCE_DIR / "templates"
STATIC_DIR = RESOURCE_DIR / "static"
DATA_DIR = Path.home() / ".loudcloudproblems"
HISTORY_DB = DATA_DIR / "scan_history.sqlite3"

# Make the repo-local cloud_misconfig_scanner package importable.
sys.path.insert(0, str(BASE_DIR.parent / "src"))

from cloud_misconfig_scanner.fixtures import load_fixture_clients  # noqa: E402
from cloud_misconfig_scanner.iam import scan_iam  # noqa: E402
from cloud_misconfig_scanner.s3 import scan_s3  # noqa: E402

app = Flask(
    __name__,
    template_folder=str(TEMPLATES_DIR),
    static_folder=str(STATIC_DIR),
    static_url_path="/static",
)

FIXTURE_LABELS = {
    "clean-account": "Clean account (no findings expected)",
    "mixed-findings": "Mixed account (sample from README)",
    "high-risk-account": "High-risk account (many findings)",
}


def _connect_history_db() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(HISTORY_DB)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at TEXT NOT NULL,
            mode TEXT NOT NULL,
            fixture_id TEXT,
            account_id TEXT
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            resource TEXT NOT NULL,
            service TEXT NOT NULL,
            check_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            finding_json TEXT NOT NULL,
            source_json TEXT,
            FOREIGN KEY (run_id) REFERENCES scan_runs(id)
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_scan_findings_resource ON scan_findings(resource)"
    )
    connection.commit()
    return connection


def _list_fixtures() -> list[dict[str, str]]:
    fixtures = []
    for path in sorted(FIXTURES_DIR.glob("*.json")):
        key = path.stem
        fixtures.append({"id": key, "label": FIXTURE_LABELS.get(key, key)})
    return fixtures


def _load_fixture_payload(fixture_id: str) -> dict[str, Any]:
    path = FIXTURES_DIR / f"{fixture_id}.json"
    if not path.exists():
        raise FileNotFoundError(fixture_id)
    return json.loads(path.read_text(encoding="utf-8"))


def _run_scan(fixture_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    path = FIXTURES_DIR / f"{fixture_id}.json"
    payload = _load_fixture_payload(fixture_id)
    clients = load_fixture_clients(path)
    findings = scan_s3(clients.s3, account_id=clients.account_id)
    findings.extend(scan_iam(clients.iam, account_id=clients.account_id))
    findings.sort(key=lambda f: (-f.severity.value, f.service, f.resource))
    return [f.to_dict() for f in findings], payload


def _source_fragment_for_resource(payload: dict[str, Any], resource: str) -> dict[str, Any] | None:
    if resource.startswith("s3://"):
        bucket_name = resource.removeprefix("s3://")
        bucket = payload.get("s3", {}).get("buckets", {}).get(bucket_name)
        if bucket is None:
            return None
        return {"resource": resource, "bucket": bucket_name, "source": bucket}

    if resource.startswith("iam:user/"):
        user_name = resource.removeprefix("iam:user/")
        return _iam_identity_fragment(payload, "users", "UserName", user_name, resource)

    if resource.startswith("iam:role/"):
        role_name = resource.removeprefix("iam:role/")
        return _iam_identity_fragment(payload, "roles", "RoleName", role_name, resource)

    if resource.startswith("iam:group/"):
        group_name = resource.removeprefix("iam:group/")
        return _iam_identity_fragment(payload, "groups", "GroupName", group_name, resource)

    return None


def _iam_identity_fragment(
    payload: dict[str, Any],
    collection: str,
    key: str,
    name: str,
    resource: str,
) -> dict[str, Any] | None:
    for identity in payload.get("iam", {}).get(collection, []):
        if identity.get(key) == name:
            attached_policy_documents = {}
            for policy in identity.get("AttachedPolicies", []):
                policy_arn = policy.get("PolicyArn")
                if policy_arn in payload.get("iam", {}).get("policies", {}):
                    attached_policy_documents[policy_arn] = payload["iam"]["policies"][policy_arn]
            return {
                "resource": resource,
                "identity_type": collection[:-1],
                "source": identity,
                "attached_policy_documents": attached_policy_documents,
            }
    return None


def _record_scan(
    fixture_id: str,
    account_id: str | None,
    findings: list[dict[str, Any]],
    payload: dict[str, Any],
) -> int:
    scanned_at = datetime.now(timezone.utc).isoformat()
    with _connect_history_db() as connection:
        cursor = connection.execute(
            """
            INSERT INTO scan_runs (scanned_at, mode, fixture_id, account_id)
            VALUES (?, ?, ?, ?)
            """,
            (scanned_at, "fixture", fixture_id, account_id),
        )
        run_id = int(cursor.lastrowid)
        for finding in findings:
            source = _source_fragment_for_resource(payload, finding["resource"])
            connection.execute(
                """
                INSERT INTO scan_findings (
                    run_id, resource, service, check_id, severity, title,
                    finding_json, source_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    finding["resource"],
                    finding["service"],
                    finding["check_id"],
                    finding["severity"],
                    finding["title"],
                    json.dumps(finding, sort_keys=True),
                    json.dumps(source, sort_keys=True) if source is not None else None,
                ),
            )
        connection.commit()
    return run_id


def _history_for_resource(resource: str) -> list[dict[str, Any]]:
    with _connect_history_db() as connection:
        rows = connection.execute(
            """
            SELECT
                scan_runs.id AS run_id,
                scan_runs.scanned_at,
                scan_runs.mode,
                scan_runs.fixture_id,
                scan_runs.account_id,
                scan_findings.service,
                scan_findings.check_id,
                scan_findings.severity,
                scan_findings.title,
                scan_findings.finding_json
            FROM scan_findings
            JOIN scan_runs ON scan_runs.id = scan_findings.run_id
            WHERE scan_findings.resource = ?
            ORDER BY scan_runs.scanned_at DESC, scan_findings.id DESC
            LIMIT 50
            """,
            (resource,),
        ).fetchall()

    history = []
    for row in rows:
        history.append(
            {
                "run_id": row["run_id"],
                "scanned_at": row["scanned_at"],
                "mode": row["mode"],
                "fixture_id": row["fixture_id"],
                "account_id": row["account_id"],
                "service": row["service"],
                "check_id": row["check_id"],
                "severity": row["severity"],
                "title": row["title"],
                "finding": json.loads(row["finding_json"]),
            }
        )
    return history


@app.route("/")
def index():
    return render_template("index.html", fixtures=_list_fixtures())


@app.get("/favicon.ico")
def favicon():
    return send_from_directory(STATIC_DIR, "loudcloudproblems.ico", mimetype="image/x-icon")


@app.route("/api/fixtures")
def api_fixtures():
    return jsonify(_list_fixtures())


@app.route("/api/scan")
def api_scan():
    fixture_id = request.args.get("fixture", "mixed-findings")
    try:
        findings, payload = _run_scan(fixture_id)
    except FileNotFoundError:
        return jsonify({"error": f"unknown fixture '{fixture_id}'"}), 404
    except json.JSONDecodeError as exc:
        return jsonify({"error": f"invalid fixture JSON: {exc}"}), 400

    run_id = _record_scan(fixture_id, payload.get("account_id"), findings, payload)
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        summary[finding["severity"]] = summary.get(finding["severity"], 0) + 1

    return jsonify(
        {
            "fixture": fixture_id,
            "mode": "fixture",
            "run_id": run_id,
            "summary": summary,
            "findings": findings,
        }
    )


@app.route("/api/resource/raw")
def api_resource_raw():
    fixture_id = request.args.get("fixture", "mixed-findings")
    resource = request.args.get("resource", "")
    if not resource:
        return jsonify({"error": "resource is required"}), 400

    try:
        payload = _load_fixture_payload(fixture_id)
    except FileNotFoundError:
        return jsonify({"error": f"unknown fixture '{fixture_id}'"}), 404
    except json.JSONDecodeError as exc:
        return jsonify({"error": f"invalid fixture JSON: {exc}"}), 400

    source = _source_fragment_for_resource(payload, resource)
    if source is None:
        return jsonify({"error": f"no raw source data found for '{resource}'"}), 404
    return jsonify(source)


@app.route("/api/resource/history")
def api_resource_history():
    resource = request.args.get("resource", "")
    if not resource:
        return jsonify({"error": "resource is required"}), 400
    return jsonify({"resource": resource, "history": _history_for_resource(resource)})


if __name__ == "__main__":
    app.run(debug=False, port=5050)
