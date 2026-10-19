$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
python -m uvicorn app:app --host 0.0.0.0 --port 8001
