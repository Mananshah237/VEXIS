@echo off
REM ============================================================================
REM  VEXIS - one-command launcher (Windows)
REM  Creates a local .env with generated dev secrets on first run, then brings
REM  the whole stack up with Docker Compose.
REM ============================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

REM --- Preflight: Docker must be installed and running ------------------------
where docker >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Docker was not found on PATH. Install Docker Desktop, then re-run.
  exit /b 1
)
docker info >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Docker is installed but not running. Start Docker Desktop, then re-run.
  exit /b 1
)

REM --- First run: generate a local .env with strong random dev secrets --------
if not exist ".env" (
  echo Creating .env with generated local-dev secrets...
  for /f "delims=" %%i in ('powershell -NoProfile -Command "$b=New-Object byte[] 32;[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b);[BitConverter]::ToString($b).Replace('-','')"') do set "JWT=%%i"
  for /f "delims=" %%i in ('powershell -NoProfile -Command "$b=New-Object byte[] 24;[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b);[BitConverter]::ToString($b).Replace('-','')"') do set "MINIO=%%i"
  for /f "delims=" %%i in ('powershell -NoProfile -Command "$b=New-Object byte[] 32;[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b);[Convert]::ToBase64String($b)"') do set "NEXTAUTH=%%i"
  (
    echo VEXIS_ENV=dev
    echo JWT_SECRET=!JWT!
    echo NEXTAUTH_SECRET=!NEXTAUTH!
    echo MINIO_ACCESS_KEY=vexis
    echo MINIO_SECRET_KEY=!MINIO!
    echo ENCRYPTION_KEY=
    echo GOOGLE_API_KEY=
    echo ANTHROPIC_API_KEY=
    echo GITHUB_CLIENT_ID=
    echo GITHUB_CLIENT_SECRET=
  ) > .env
  echo .env created. ^(Add GOOGLE_API_KEY for AI reasoning passes; taint engine works without it.^)
) else (
  echo Using existing .env
)

echo.
echo Starting VEXIS  ^(docker compose up --build -d^) ...
docker compose up --build -d
if errorlevel 1 (
  echo [ERROR] docker compose failed. See the output above.
  exit /b 1
)

echo.
echo ============================================================
echo  VEXIS is starting up.
echo    Frontend : http://localhost:3000
echo    API      : http://localhost:8000/health
echo  Logs : docker compose logs -f      Stop : docker compose down
echo ============================================================
endlocal
