@echo off
title Blockchain P2P 6-Node Network Launcher
echo Dang khoi dong mang luoi Blockchain P2P 6 Node...

where py >nul 2>&1
if %errorlevel% equ 0 (
    py -3.12 start_interactive_network.py 2>nul || py start_interactive_network.py
    goto end
)

where python >nul 2>&1
if %errorlevel% equ 0 (
    python start_interactive_network.py
    goto end
)

where python3 >nul 2>&1
if %errorlevel% equ 0 (
    python3 start_interactive_network.py
    goto end
)

echo [ERROR] Khong tim thay Python! Vui long cai dat Python 3.
pause

:end
pause
