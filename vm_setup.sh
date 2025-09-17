#!/bin/bash
#
# RexPloit Automated Setup Script for Cloud VMs
# For authorized security testing only
#
# This script will install RexPloit and all its dependencies
# on a fresh Ubuntu or Debian-based system.
#

# Exit on any error and set strict mode
set -euo pipefail

# Set IFS to secure default
IFS=$'\n\t'

# Function to handle errors
error_exit() {
    echo "ERROR: $1" >&2
    exit 1
}

# Function to log messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

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
    error_exit "This script must be run as root. Try 'sudo $0'"
fi

# Validate environment
if ! command -v apt-get &> /dev/null; then
    error_exit "apt-get not found. This script requires Ubuntu or Debian."
fi

# Detect OS
if [ -f /etc/os-release ]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    OS="${NAME:-Unknown}"
    VER="${VERSION_ID:-Unknown}"
else
    error_exit "Cannot detect operating system. This script requires Ubuntu or Debian."
fi

log_message "Detected OS: $OS $VER"
log_message "Starting RexPloit setup..."

# Update system
log_message "Updating system packages..."
apt-get update || error_exit "Failed to update package lists"
apt-get upgrade -y || error_exit "Failed to upgrade packages"

# Install dependencies
log_message "Installing required packages..."
apt-get install -y git python3 python3-pip python3-venv nmap netcat-openbsd curl wget unzip || \
    error_exit "Failed to install required packages"

# Setup firewall (ufw)
log_message "Configuring firewall..."
apt-get install -y ufw || error_exit "Failed to install ufw"
ufw allow ssh || error_exit "Failed to configure SSH in firewall"
ufw allow 4444/tcp || error_exit "Failed to configure port 4444 in firewall"
ufw allow 8080/tcp || error_exit "Failed to configure port 8080 in firewall"
ufw allow 8888/tcp || error_exit "Failed to configure port 8888 in firewall"
ufw --force enable || error_exit "Failed to enable firewall"

# Clone RexPloit
log_message "Cloning RexPloit repository..."
cd /opt || error_exit "Failed to change to /opt directory"

# Clean up any existing installation
if [ -d "rexploit" ]; then
    log_message "Removing existing RexPloit installation..."
    rm -rf rexploit
fi

git clone https://github.com/cxb3rf1lth/Moloch.git rexploit || \
    error_exit "Failed to clone RexPloit repository"
cd rexploit || error_exit "Failed to enter RexPloit directory"

# Setup Python environment
log_message "Setting up Python virtual environment..."
python3 -m venv .venv || error_exit "Failed to create virtual environment"
# shellcheck source=/dev/null
source .venv/bin/activate || error_exit "Failed to activate virtual environment"
pip install --upgrade pip || error_exit "Failed to upgrade pip"
pip install -r requirements.txt || error_exit "Failed to install Python requirements"

# Create convenient aliases
log_message "Creating convenient aliases..."
cat > /etc/profile.d/rexploit.sh << 'EOF'
#!/bin/bash

# RexPloit aliases
alias rexploit="cd /opt/rexploit && source .venv/bin/activate && python3 rexploit.py"
alias rexploit-cli="cd /opt/rexploit && source .venv/bin/activate && python3 rexploit.py --cli"
EOF

chmod +x /etc/profile.d/rexploit.sh || error_exit "Failed to set permissions on alias script"

# Setup C2 frameworks
log_message "Setting up C2 frameworks..."
mkdir -p /opt/rexploit/c2_frameworks
cd /opt/rexploit/c2_frameworks || error_exit "Failed to enter c2_frameworks directory"

# Clone Villain
log_message "Cloning Villain C2 framework..."
if ! git clone https://github.com/t3l3machus/Villain villain; then
    log_message "Warning: Failed to clone Villain framework"
fi

# Clone HoaxShell
log_message "Cloning HoaxShell C2 framework..."
if ! git clone https://github.com/t3l3machus/hoaxshell hoaxshell; then
    log_message "Warning: Failed to clone HoaxShell framework"
fi

# Create sliver directory (user will need to download sliver binary separately)
mkdir -p sliver

# Set secure permissions
log_message "Setting secure permissions..."
chown -R root:root /opt/rexploit || error_exit "Failed to set ownership"
chmod -R 755 /opt/rexploit || error_exit "Failed to set permissions"
chmod 750 /opt/rexploit/c2_frameworks || error_exit "Failed to set C2 permissions"

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
log_message "RexPloit setup completed successfully!"

echo "
[+] RexPloit setup completed successfully!

You can now use the following commands:
  rexploit       - Launch RexPloit with UI
  rexploit-cli   - Launch RexPloit in CLI mode

RexPloit is installed in: /opt/rexploit

IMPORTANT: This tool is for authorized security testing only.
"

# Source the aliases for current session
# shellcheck source=/dev/null
source /etc/profile.d/rexploit.sh || log_message "Warning: Failed to source aliases"

log_message "Setup completed at $(date)"