@echo off
title Phishing Detection System
echo ========================================================
echo   Starting Phishing Detection System (CNS Project)...
echo ========================================================
echo.
cd /d "%~dp0"
pip install -r requirements.txt --quiet
echo Starting Flask server...
start http://127.0.0.1:5000
python app.py
pause
