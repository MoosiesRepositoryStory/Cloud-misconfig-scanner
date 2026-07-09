# Cloud Misconfiguration Scanner - Dashboard

A browser dashboard for the Cloud Misconfiguration Scanner CLI. It runs the same S3 and IAM detection logic from `../src/cloud_misconfig_scanner` against Boto3-shaped JSON fixtures, then shows the findings in a filterable table with severity summary cards.

This is a demo app. It only reads local JSON fixtures under `fixtures/`, so it is safe to run and screen-record without AWS credentials or network calls.

## What's included

- `app.py` - Flask app that adds `../src` to `sys.path` and imports `scan_s3`, `scan_iam`, and `load_fixture_clients` directly from the scanner package in this repo.
- `desktop.py` - runs `app.py`'s Flask server in a background thread and opens it in a native PyWebView window, so the dashboard launches as a standalone desktop app instead of requiring a browser.
- `fixtures/`
  - `clean-account.json` - a properly configured account. Expect 0 findings.
  - `mixed-findings.json` - the original sample from the scanner README. Expect 8 findings.
  - `high-risk-account.json` - a deliberately bad account that trips every check the scanner implements. Expect 13 findings.
- `templates/index.html` - single-page dashboard with a fixture dropdown, severity filter, JSON export, and CSV export.

## Run it

Run these commands from within this repository. You do not need to separately install the scanner package because `dashboard/app.py` imports it directly from `../src`.

```bash
python -m venv .venv
source .venv/bin/activate        # or .venv\Scripts\Activate.ps1 on Windows
pip install -r dashboard/requirements.txt
python dashboard/app.py
```

Then open http://127.0.0.1:5050. Pick a fixture from the dropdown, click **Run Scan**, filter by severity, and export the findings as JSON or CSV.

Run `python dashboard/desktop.py` for the desktop app, or `python dashboard/app.py` + open browser for web mode.

You can also call the API directly:

```bash
curl "http://127.0.0.1:5050/api/scan?fixture=high-risk-account"
```

## Pointing It At A Real AWS Account

The dashboard only calls `scan_s3` and `scan_iam` against fixture clients right now. To scan a real account instead:

1. Make sure Boto3 is installed in the environment.
2. In `app.py`, import `create_boto3_clients` from `cloud_misconfig_scanner.aws`.
3. Add a code path that builds `AwsClients` from a profile and region instead of a fixture file.
4. Do not expose that path on a publicly hosted version of this app. Treat live-account scanning as a local-only feature, since it needs read access to IAM and S3 configuration.

## Why This Exists

The scanner is a CLI tool, which is great for CI with options like `--fail-on HIGH`. This dashboard wraps the same detection logic in a UI so the project is demoable: pick an account fixture, see severity-ranked findings, and export a report.
