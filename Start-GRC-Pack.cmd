@echo off
cd /d "%~dp0"
set PYTHONPATH=%CD%
set OUT_DIR=%CD%\out
set DRY_RUN=1
set GRC_LIVE_SCAN=0
set CISO_PUSH=0
set RISKREADY_PUSH=0
powershell -ExecutionPolicy Bypass -File "%~dp0scripts\start-product.ps1"
