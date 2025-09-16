# RexPloit Quick Start Guide

This document provides a quick overview of how to get started with RexPloit, the professional penetration testing framework.

## Getting Started in 5 Minutes

### Prerequisites
- Python 3.8 or higher
- Git
- Internet connection (for dependency installation)

### Step 1: Clone the Repository
```bash
git clone https://github.com/cxb3rf1lth/Moloch.git
cd Moloch
```

### Step 2: Install Dependencies
```bash
python3 rexploit.py --install
```
This will automatically detect and install all required dependencies.

### Step 3: Launch RexPloit
```bash
python3 rexploit.py
```
You'll be presented with the main RexPloit interface.

## Basic Operations

### Generating a Payload
1. Select "Payload Generator" from the main menu
2. Choose payload type (Python, PowerShell, Bash, etc.)
3. Enter your listener host and port
4. Select encoding/obfuscation options if desired
5. Click "Generate"

### Starting a C2 Framework
1. Select "C2 Manager" from the main menu
2. Choose your preferred framework (Sliver, Villain, HoaxShell)
3. Configure listening options
4. Click "Start Framework"

### Running a Vulnerability Scan
1. Select "Vulnerability Scanner" from the main menu
2. Enter the target URL or IP address
3. Select scan intensity and options
4. Click "Start Scan"
5. Review findings in the results window

## Command Line Usage Examples

### Generate Python Payload
```bash
python3 rexploit.py --cli --payload python --lhost 192.168.1.10 --lport 4444
```

### Run Quick Vulnerability Scan
```bash
python3 rexploit.py --cli --scan https://target-domain.com
```

### Start Sliver C2 Framework
```bash
python3 rexploit.py --cli --c2 sliver
```

## Additional Resources
- For full documentation, see the README.md
- For troubleshooting, check the logs in the logs/ directory
- For updates and new features, see the GitHub repository