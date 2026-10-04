#!/bin/bash
# ==============================================================================
# Blockchain P2P 6-Node Network Launcher for Linux (Kali Linux, Ubuntu) & macOS
# ==============================================================================

echo "=========================================================================="
echo "  KHOI CHAY MANG BLOCKCHAIN P2P 6 NODE (LINUX / KALI / MACOS)"
echo "=========================================================================="

if command -v python3 &>/dev/null; then
    PYTHON_CMD="python3"
elif command -v python &>/dev/null; then
    PYTHON_CMD="python"
elif command -v py &>/dev/null; then
    PYTHON_CMD="py"
else
    echo "[ERROR] Khong tim thay Python! Vui long cai dat Python: sudo apt install python3"
    exit 1
fi

echo "[*] Su dung Python interpreter: $PYTHON_CMD"
$PYTHON_CMD start_interactive_network.py
