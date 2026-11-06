@echo off
echo ==============================================================
echo       AICTE SmartVerify AI - Local One-Click Prototype
echo                Smart India Hackathon 2026
echo ==============================================================
echo [1/3] Generating synthetic dataset and verifying signatures...
python data\generator.py

echo [2/3] Starting AICTE SmartVerify AI Backend (FastAPI on Port 8000)...
start "AICTE SmartVerify Backend" python backend\main.py

echo [3/3] System is launching!
echo Backend API available at: http://localhost:8000
echo Officer Portal & Scrutiny UI: http://localhost:8000
echo ==============================================================
pause
