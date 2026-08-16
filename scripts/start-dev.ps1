$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "Starting VulnShield dev environment..." -ForegroundColor Cyan

# Ensure docker database is up
Write-Host "Checking PostgreSQL container..." -ForegroundColor Yellow
try {
  docker compose up -d postgres | Out-Null
} catch {
  Write-Warning "docker compose failed; ensure Docker Desktop is running."
}

# Ensure required runtime env is available for Prisma / API
$env:DATABASE_URL = 'postgresql://vulnshield:vulnshield123@localhost:5433/vulnshield'
$env:PORT = '3005'
$env:GITHUB_TOKEN = if ($env:GITHUB_TOKEN) { $env:GITHUB_TOKEN } else { 'ghp_dummy' }

Write-Host "Launching API on http://localhost:3005" -ForegroundColor Green
Start-Process powershell -ArgumentList @(
  '-NoExit',
  '-Command',
  "Set-Location '$root'; `$env:DATABASE_URL='postgresql://vulnshield:vulnshield123@localhost:5433/vulnshield'; `$env:PORT='3005'; `$env:GITHUB_TOKEN='ghp_dummy'; pnpm --filter @vuln-shield/api dev"
) -WorkingDirectory $root

Start-Sleep -Seconds 3

Write-Host "Launching web app on http://localhost:3000" -ForegroundColor Green
Start-Process powershell -ArgumentList @(
  '-NoExit',
  '-Command',
  "Set-Location '$root'; pnpm --filter @vuln-shield/web dev"
) -WorkingDirectory $root

Write-Host "" 
Write-Host "VulnShield is starting." -ForegroundColor Cyan
Write-Host "API: http://localhost:3005" -ForegroundColor Cyan
Write-Host "Web: http://localhost:3000" -ForegroundColor Cyan
