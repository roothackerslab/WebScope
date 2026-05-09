#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# WebScope Pro v2.1 - Quick Setup Script
# By: Mughal__Hacker | RootHackersLab
# ═══════════════════════════════════════════════════════════════════

echo "
 ██╗    ██╗███████╗██████╗ ███████╗ ██████╗ ██████╗ ██████╗ ███████╗
 ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
 ██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ██║   ██║██████╔╝█████╗  
 ██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  
 ╚███╔███╔╝███████╗██████╔╝███████║╚██████╗╚██████╔╝██║     ███████╗
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
"
echo "═══════════════════════════════════════════════════════════════════"
echo "  WebScope Pro v2.1 - Installation Script"
echo "  By: Mughal__Hacker | RootHackersLab"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

# Check Python installation
echo "[*] Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
    PIP_CMD="pip3"
    echo "[+] Python3 found: $(python3 --version)"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
    PIP_CMD="pip"
    echo "[+] Python found: $(python --version)"
else
    echo "[-] Python not found! Please install Python 3.7 or higher."
    exit 1
fi

echo ""
echo "[*] Installing dependencies..."
$PIP_CMD install -r requirements.txt

if [ $? -eq 0 ]; then
    echo ""
    echo "[+] Installation completed successfully!"
    echo ""
    echo "═══════════════════════════════════════════════════════════════════"
    echo "  USAGE:"
    echo "    $PYTHON_CMD WebScope.py example.com"
    echo "    $PYTHON_CMD WebScope.py example.com -o html"
    echo "    $PYTHON_CMD WebScope.py example.com -o json"
    echo "    $PYTHON_CMD WebScope.py --help"
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
    echo "[+] Making WebScope.py executable..."
    chmod +x WebScope.py
    echo "[+] Done! Happy Hacking! 💀🔥"
    echo ""
else
    echo ""
    echo "[-] Installation failed! Please check the errors above."
    exit 1
fi

