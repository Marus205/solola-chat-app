@echo off
cd /d "%~dp0"

set PYTHON_CMD=

where py >nul 2>nul
if %ERRORLEVEL%==0 (
    set PYTHON_CMD=py -3
) else (
    where python >nul 2>nul
    if %ERRORLEVEL%==0 (
        set PYTHON_CMD=python
    )
)

if "%PYTHON_CMD%"=="" (
    echo.
    echo ERREUR : Python n'est pas reconnu par Windows.
    echo Installe Python puis coche "Add python.exe to PATH".
    echo.
    pause
    exit /b 1
)

if not exist .venv (
    %PYTHON_CMD% -m venv .venv
)

call .venv\Scripts\activate.bat

.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r requirements.txt

if not exist .env copy .env.example .env

.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
