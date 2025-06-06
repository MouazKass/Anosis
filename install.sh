#!/bin/bash
# Anosis Armour Installation Script

set -e

echo "======================================"
echo "  Anosis Armour Installation Script"
echo "======================================"
echo ""

# Check if running on supported OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "[✓] Linux detected"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "[✓] macOS detected"
else
    echo "[✗] Unsupported OS: $OSTYPE"
    exit 1
fi

# Check Python version
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    echo "[✓] Python $PYTHON_VERSION found"
    
    # Check if Python 3.8+
    if python3 -c 'import sys; exit(0 if sys.version_info >= (3, 8) else 1)'; then
        echo "[✓] Python version is 3.8+"
    else
        echo "[✗] Python 3.8+ required"
        exit 1
    fi
else
    echo "[✗] Python 3 not found"
    exit 1
fi

# Check for pip
if ! command -v pip3 &> /dev/null; then
    echo "[✗] pip3 not found. Please install python3-pip"
    exit 1
fi

# Install system dependencies
echo ""
echo "Installing system dependencies..."

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    if command -v apt-get &> /dev/null; then
        # Debian/Ubuntu
        echo "Detected Debian/Ubuntu system"
        echo "Please run: sudo apt-get install python3-dev libpcap-dev"
    elif command -v yum &> /dev/null; then
        # RHEL/CentOS
        echo "Detected RHEL/CentOS system"
        echo "Please run: sudo yum install python3-devel libpcap-devel"
    elif command -v pacman &> /dev/null; then
        # Arch
        echo "Detected Arch Linux system"
        echo "Please run: sudo pacman -S python libpcap"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    if command -v brew &> /dev/null; then
        echo "Installing libpcap via Homebrew..."
        brew install libpcap
    else
        echo "[!] Homebrew not found. Please install Homebrew first."
        echo "Visit: https://brew.sh"
    fi
fi

# Create virtual environment (optional)
read -p "Create virtual environment? (recommended) [Y/n]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Nn]$ ]]; then
    echo "Skipping virtual environment..."
else
    echo "Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    echo "[✓] Virtual environment created and activated"
fi

# Install Python dependencies
echo ""
echo "Installing Python dependencies..."
pip3 install --upgrade pip
pip3 install -r requirements.txt

# Make script executable
chmod +x anosis_armour.py

# Create directories
echo ""
echo "Creating directories..."
mkdir -p ~/.anosis/{logs,reports}
echo "[✓] Directories created"

# Test installation
echo ""
echo "Testing installation..."
if python3 anosis.py --version; then
    echo "[✓] Installation successful!"
else
    echo "[✗] Installation test failed"
    exit 1
fi

# Final instructions
echo ""
echo "======================================"
echo "  Installation Complete!"
echo "======================================"
echo ""
echo "Usage examples:"
echo "  python3 anosis.py info"
echo "  python3 anosis.py analyze capture.pcap"
echo "  sudo python3 anosis.py capture -i eth0 -o traffic.pcap"
echo ""
echo "For system-wide installation:"
echo "  sudo pip3 install -e ."
echo ""
echo "Happy hunting!"
