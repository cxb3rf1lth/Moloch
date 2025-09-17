# RexPloit - Professional Penetration Testing Framework

<div align="center">
  <img src="https://img.shields.io/badge/Version-2.0.0%20(Cerberus)-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.8%2B-brightgreen.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
  <img src="https://img.shields.io/badge/Interface-CLI-green.svg" alt="Interface">
  <br>
  <strong>FOR AUTHORIZED SECURITY TESTING ONLY</strong>
</div>

## 🔒 Overview

RexPloit is a comprehensive penetration testing framework designed for security professionals conducting authorized assessments. Built with a professional command-line interface, it integrates multiple Command & Control frameworks, advanced payload generation, and vulnerability scanning capabilities.

> ⚠️ **IMPORTANT**: This tool is for professional security testing only. Only use on systems you have explicit permission to test.

## 🌟 Key Features

- **Professional CLI Interface**: Advanced command-line interface with subcommands and interactive mode
- **Multi-C2 Integration**: Supports Sliver, Villain, and HoaxShell frameworks
- **Advanced Payload Generation**: Create customized payloads with encoding/obfuscation
- **Secure Injection**: Deploy payloads via multiple vectors with comprehensive logging
- **Vulnerability Scanning**: Identify security issues with severity scoring
- **Detailed Reporting**: Generate professional assessment reports in multiple formats
- **Interactive Mode**: Full-featured interactive shell for advanced operations
- **Comprehensive Help**: Built-in help system with examples and usage guides

## 🎨 Interface Modes

### Command-Line Mode (Default)
```bash
# Generate payloads
rexploit payload --type python --lhost 192.168.1.100 --lport 4444

# Manage C2 frameworks  
rexploit c2 --framework sliver --start

# Perform security scans
rexploit scan --target 192.168.1.0/24 --type vuln

# Generate reports
rexploit report --format html --output /tmp/report.html
```

### Interactive Mode
```bash
# Launch interactive shell
rexploit --interactive

# Then use commands like:
rexploit> payload python 192.168.1.100 4444
rexploit> c2 start sliver
rexploit> scan vuln 192.168.1.100
rexploit> help
```

## 📋 Requirements

- Python 3.8+
- Required Python packages:
  - rich
  - textual
  - requests
  - urllib3
- External C2 frameworks:
  - Sliver: [BishopFox/sliver](https://github.com/BishopFox/sliver)
  - Villain: [t3l3machus/Villain](https://github.com/t3l3machus/Villain)
  - HoaxShell: [t3l3machus/hoaxshell](https://github.com/t3l3machus/hoaxshell)

## 🚀 Installation & Usage

### Quick Start

```bash
git clone https://github.com/cxb3rf1lth/Moloch.git
cd Moloch
pip3 install -r requirements.txt
./rexploit --help
```

### Basic Usage

```bash
# View all available commands
./rexploit --help

# Generate a Python reverse shell payload
./rexploit payload --type python --lhost 192.168.1.100 --lport 4444

# Start Sliver C2 framework
./rexploit c2 --framework sliver --start

# Perform vulnerability scan
./rexploit scan --target 192.168.1.100 --type vuln

# Generate HTML report
./rexploit report --format html

# Enter interactive mode
./rexploit --interactive
```

### Automatic Dependency Installation

```bash
git clone https://github.com/cxb3rf1lth/Moloch.git
cd Moloch
python3 unified_rexploit.py --install
```

### Manual Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/cxb3rf1lth/Moloch.git
   cd Moloch
   ```

2. **Install Python dependencies:**
   ```bash
   pip3 install -r requirements.txt
   ```

3. **Set up C2 frameworks:**
   ```bash
   # Create C2 frameworks directory
   mkdir -p c2_frameworks
   
   # Clone Villain
   git clone https://github.com/t3l3machus/Villain c2_frameworks/villain
   
   # Clone HoaxShell
   git clone https://github.com/t3l3machus/hoaxshell c2_frameworks/hoaxshell
   
   # Download Sliver (ensure you get the appropriate version for your system)
   mkdir -p c2_frameworks/sliver
   # Download from https://github.com/BishopFox/sliver/releases
   ```

## 🎮 Usage

### Starting the Framework

```bash
python3 rexploit.py
```

### Command Line Options

```bash
# Show help
python3 rexploit.py --help

# Run in CLI mode with specific payload generation
python3 rexploit.py --cli --payload python --lhost 192.168.1.10 --lport 4444

# Run vulnerability scan
python3 rexploit.py --cli --scan https://target-domain.com

# Start specific C2 framework
python3 rexploit.py --cli --c2 sliver

# Generate encoded and obfuscated payload
python3 rexploit.py --cli --payload powershell --lhost 192.168.1.10 --lport 4444 --encode --obfuscate

# Run with legacy UI mode
python3 rexploit.py --legacy

# Check dependencies without installing
python3 rexploit.py --check

# Run test suite
python3 rexploit.py --test
```

### Framework Workflow

1. **Authorization Check**: Confirm you have permission to test targets
2. **Dependencies Check**: Verify all required components
3. **C2 Framework Selection**: Choose and start a C2 framework
4. **Payload Generation**: Create appropriate payload for target
5. **Payload Deployment**: Inject payload via selected vector
6. **Vulnerability Scanning**: Identify and assess security issues
7. **Reporting**: Generate comprehensive assessment report

## 🗂️ Project Structure

```
.
├── rexploit.py             # Main application script
├── unified_rexploit.py     # Command-line interface entry point
├── dependency_manager.py   # Manages required dependencies
├── enhanced_ui.py          # Modern TUI components
├── enhancements.py         # Extended functionality modules
├── master_integrator.py    # Component integration management
├── config/                 # Configuration files
│   └── rexploit_config.json
├── payloads/               # Generated payloads
├── logs/                   # Activity and connection logs
├── reports/                # Assessment reports
├── c2_frameworks/          # External C2 tools
│   ├── sliver/
│   ├── villain/
│   └── hoaxshell/
└── tests/                  # Test suite
```

## 🔧 Advanced Configuration

The default configuration is stored in `config/rexploit_config.json`. You can customize settings by editing this file:

```json
{
  "listener_host": "127.0.0.1",
  "listener_port": 4444,
  "default_c2": "sliver",
  "log_level": "INFO",
  "auto_install": true,
  "payload_options": {
    "encode": true,
    "obfuscate": false
  }
}
```

## 🛠 Development

### Running Tests

```bash
# Run all tests
python3 run_tests.py --all

# Run validation tests
python3 validate_all.py

# Run specific test module
python3 run_tests.py --module logger
```

### Adding New Features

1. Update the appropriate module file
2. Add test cases in the `tests/` directory
3. Run validation tests to ensure compatibility
4. Update documentation as needed

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

RexPloit is intended for use by cybersecurity professionals in controlled, authorized security testing environments only. Unauthorized use against systems without explicit permission is illegal and unethical. The developers assume no liability for misuse of this software.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📬 Contact

For questions, issues, or feature requests, please open an issue on the GitHub repository.

---

<div align="center">
  <p>RexPloit v2.0.0 "Cerberus" - Professional Security Testing Framework</p>
  <p>FOR AUTHORIZED SECURITY TESTING ONLY</p>
</div>