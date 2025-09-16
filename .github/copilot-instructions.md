# Copilot Instructions for Moloch (RexPloit)

## Overview
This repository contains RexPloit, a professional penetration testing framework for authorized security testing only. The main tool is `rexploit.py`, which provides a rich UI (Textual/Rich) and integrates with multiple C2 frameworks, payload generation, injection, and vulnerability scanning.

## Architecture
- **Main Entry Point:** `rexploit.py` (run as a script)
- **UI:** Built with Textual and Rich for interactive console and dashboard
- **C2 Frameworks:** Supports Sliver, Villain, HoaxShell (see `C2Manager` class)
- **Payloads:** Generated and stored in `payloads/` directory
- **Logs:** Activity and connection logs in `logs/` directory
- **Config:** Persistent config in `config/rexploit_config.json` (auto-created if missing)

## Developer Workflows
- **Run the tool:** `python3 rexploit.py` (ensure dependencies installed)
- **Authorization Prompt:** Tool enforces explicit authorization before running
- **C2 Setup:** Sliver requires `sliver-server` binary; Villain/HoaxShell require their respective Python scripts cloned into `c2_frameworks/`
- **Payload Generation:** UI prompts for type, host, port, encoding, obfuscation
- **Injection:** Simulated via multiple vectors; results shown in UI
- **Vulnerability Scanning:** Simulated scan with findings table

## Project-Specific Patterns
- **Config Auto-creation:** If config file missing, default is written
- **Directory Creation:** `payloads/`, `logs/`, `c2_frameworks/` auto-created on startup
- **Logging:** Centralized via `Logger` class; connection evidence in JSON
- **UI Bindings:** Keyboard shortcuts for main actions (see `RexPloitApp.BINDINGS`)
- **Payload Metadata:** Each payload saved with metadata and checksum
- **Obfuscation/Encoding:** Payloads can be encoded (base64) and obfuscated (random comments, variable renaming)

## External Dependencies
- **Python Packages:** `rich`, `textual`, `requests`, `urllib3`
- **C2 Frameworks:**
  - Sliver: https://github.com/BishopFox/sliver
  - Villain: https://github.com/t3l3machus/Villain
  - HoaxShell: https://github.com/t3l3machus/hoaxshell

## Key Files & Directories
- `rexploit.py`: Main tool and all core logic
- `payloads/`: Generated payloads
- `logs/`: Activity and connection logs
- `config/rexploit_config.json`: Persistent configuration
- `c2_frameworks/`: External C2 scripts/binaries

## Example Usage
- Start RexPloit: `python3 rexploit.py`
- Generate payload: Use UI, select type, host, port, encoding/obfuscation
- Inject payload: Use UI, select targets, confirm deployment
- Run scan: Use UI, select target, view findings

## Conventions
- All code and UI actions are prefixed as "Professional" for clarity
- Only authorized testing is permitted; tool enforces this at runtime
- All evidence and logs are stored for audit purposes

---
For questions, see `rexploit.py` for implementation details and class structure. Update this file if major architectural changes are made.
