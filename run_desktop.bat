@echo off
setlocal
echo ==========================================================
echo  Starting Keynova Autonomous PQC Readiness Desktop App...
echo ==========================================================

cd /d "%~dp0frontend"
npm run desktop:dev
