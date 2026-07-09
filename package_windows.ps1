$ErrorActionPreference = "Stop"

.\.venv\Scripts\python.exe -m PyInstaller `
  --noconfirm `
  --clean `
  --onefile `
  --name LoudCloudProblems `
  --paths src `
  --icon "dashboard\static\loudcloudproblems.ico" `
  --add-data "dashboard\templates;dashboard\templates" `
  --add-data "dashboard\fixtures;dashboard\fixtures" `
  --add-data "dashboard\static;dashboard\static" `
  --hidden-import clr `
  --hidden-import pythonnet `
  dashboard\desktop.py
