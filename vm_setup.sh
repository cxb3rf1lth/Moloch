#!/bin/bash
#
# RexPloit Automated Setup Script for Cloud VMs
# For authorized security testing only
#
# This script will install RexPloit and all its dependencies
# on a fresh Ubuntu or Debian-based system.
#

# Exit on any error
set -e

# Display banner
echo "
 ██████╗ ███████╗██╗  ██╗██████╗ ██╗      ██████╗ ██╗████████╗
 ██╔══██╗██╔════╝╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
 ██████╔╝█████╗   ╚███╔╝ ██████╔╝██║     ██║   ██║██║   ██║   
 ██╔══██╗██╔══╝   ██╔██╗ ██╔═══╝ ██║     ██║   ██║██║   ██║   
 ██║  ██║███████╗██╔╝ ██╗██║     ███████╗╚██████╔╝██║   ██║   
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   

 Automated Cloud VM Setup Script
 FOR AUTHORIZED SECURITY TESTING ONLY
"

# Check for root privileges
if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root. Try 'sudo $0'"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
else
    echo "Cannot detect operating system. This script requires Ubuntu or Debian."
    exit 1
fi

echo "[+] Detected OS: $OS $VER"
echo "[+] Starting RexPloit setup..."

# Update system
echo "[+] Updating system packages..."
apt-get update
apt-get upgrade -y

# Install dependencies
echo "[+] Installing required packages..."
apt-get install -y git python3 python3-pip python3-venv nmap netcat-openbsd curl wget unzip

# Setup firewall (ufw)
echo "[+] Configuring firewall..."
apt-get install -y ufw
ufw allow ssh
ufw allow 4444/tcp
ufw allow 8080/tcp
ufw allow 8888/tcp
ufw --force enable

# Clone RexPloit
echo "[+] Cloning RexPloit repository..."
cd /opt
git clone https://github.com/cxb3rf1lth/Moloch.git rexploit
cd rexploit

# Setup Python environment
echo "[+] Setting up Python virtual environment..."
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Create convenient aliases
echo "[+] Creating convenient aliases..."
cat > /etc/profile.d/rexploit.sh << 'EOF'
#!/bin/bash

# RexPloit aliases
alias rexploit="cd /opt/rexploit && source .venv/bin/activate && python3 rexploit.py"
alias rexploit-cli="cd /opt/rexploit && source .venv/bin/activate && python3 rexploit.py --cli"
EOF

chmod +x /etc/profile.d/rexploit.sh

# Setup C2 frameworks
echo "[+] Setting up C2 frameworks..."
mkdir -p /opt/rexploit/c2_frameworks
cd /opt/rexploit/c2_frameworks

# Clone Villain
git clone https://github.com/t3l3machus/Villain villain

# Clone HoaxShell
git clone https://github.com/t3l3machus/hoaxshell hoaxshell

# Create sliver directory (user will need to download sliver binary separately)
mkdir -p sliver

# Set permissions
chown -R root:root /opt/rexploit

# Create welcome message
cat > /etc/motd << 'EOF'

 ██████╗ ███████╗██╗  ██╗██████╗ ██╗      ██████╗ ██╗████████╗
 ██╔══██╗██╔════╝╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
 ██████╔╝█████╗   ╚███╔╝ ██████╔╝██║     ██║   ██║██║   ██║   
 ██╔══██╗██╔══╝   ██╔██╗ ██╔═══╝ ██║     ██║   ██║██║   ██║   
 ██║  ██║███████╗██╔╝ ██╗██║     ███████╗╚██████╔╝██║   ██║   
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   
 
 Professional Penetration Testing Framework - Cloud VM
 FOR AUTHORIZED SECURITY TESTING ONLY
 
 Commands:
   rexploit       - Launch RexPloit with UI
   rexploit-cli   - Launch RexPloit in CLI mode
 
 Location:
   /opt/rexploit
 
EOF

# Final message
echo "
[+] RexPloit setup completed successfully!

You can now use the following commands:
  rexploit       - Launch RexPloit with UI
  rexploit-cli   - Launch RexPloit in CLI mode

RexPloit is installed in: /opt/rexploit

IMPORTANT: This tool is for authorized security testing only.
"

# Source the aliases
source /etc/profile.d/rexploit.sh