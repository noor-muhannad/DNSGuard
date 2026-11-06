@echo off
REM DNSGuard demo on Windows. Open http://localhost:8080/ after it starts.
cd /d "%~dp0"
python -m dnsguard_live --bundle dnsguard_bundle_v4.zip --source demo %*
