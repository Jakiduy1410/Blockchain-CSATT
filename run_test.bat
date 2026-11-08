@echo off
setlocal
pushd "%~dp0" || exit /b 1

set "SEC03_VENV=%CD%\venv"
call :find_venv
if defined SEC03_VENV_BIN goto activate
if not exist "%SEC03_VENV%" goto create

rem An existing venv can belong to Kali or another Python installation.
set "SEC03_VENV=%CD%\venv-windows"
call :find_venv
if defined SEC03_VENV_BIN goto activate
if exist "%SEC03_VENV%" (
    echo [ERROR] venv-windows khong hoat dong. Hay doi ten thu muc do va chay lai.
    goto failed
)

:create
py -3 -c "import sys" >nul 2>&1
if not errorlevel 1 (
    py -3 -m venv "%SEC03_VENV%"
) else (
    python -m venv "%SEC03_VENV%"
)
if errorlevel 1 goto failed
call :find_venv
if errorlevel 1 goto failed

:activate
call "%SEC03_VENV_BIN%\activate.bat"
if errorlevel 1 goto failed
"%SEC03_VENV_BIN%\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto failed
"%SEC03_VENV_BIN%\python.exe" run_all_attacks.py %*
set "SEC03_EXIT=%errorlevel%"
goto finish

:failed
echo [ERROR] Khong the chuan bi moi truong Python cho SEC-03.
set "SEC03_EXIT=1"

:finish
popd
pause
exit /b %SEC03_EXIT%

:find_venv
set "SEC03_VENV_BIN="
for %%D in (Scripts bin) do (
    if exist "%SEC03_VENV%\%%D\activate.bat" if exist "%SEC03_VENV%\%%D\python.exe" (
        "%SEC03_VENV%\%%D\python.exe" -c "import sys; assert sys.prefix != sys.base_prefix" >nul 2>&1
        if not errorlevel 1 (
            set "SEC03_VENV_BIN=%SEC03_VENV%\%%D"
            exit /b 0
        )
    )
)
exit /b 1
