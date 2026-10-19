$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "[1/3] Starting Kafka..." -ForegroundColor Cyan
docker compose -f "$Root\docker-compose.yml" up -d

Write-Host "[2/3] Starting AI-2 service on :8001..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList '-NoExit','-ExecutionPolicy','Bypass','-Command',"Set-Location '$Root\ai\ai2'; python -m uvicorn app:app --host 0.0.0.0 --port 8001"

Write-Host "[3/3] Starting unified backend on :8000..." -ForegroundColor Cyan
Set-Location "$Root\backend"
python -m uvicorn main:app --host 0.0.0.0 --port 8000
