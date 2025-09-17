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
    background: #1a1a2a;
    color: #e0e0e0;
    height: 3;
    padding: 0 1;
    dock: top;
    border: none;
}

Footer {
    background: #1a1a2a;
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
    padding: 1;
}

#main-content {
    background: #20203a;
    width: 1fr;
    height: 100%;
    padding: 1;
}

#tools-panel {
    background: #272736;
    border-left: tall #3d3d5c;
    width: 30;
    min-width: 25;
    max-width: 35;
    height: 100%;
    padding: 1;
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
            tabs = self.query_one(TabbedContent)
            tabs.active = tab_id
        except NoMatches:
            pass
            
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press events"""
        button_id = event.button.id
        status_panel = self.query_one(StatusPanel)
        
        # Quick tools
        if button_id == "quick-scan-network":
            status_panel.log_status("Starting network scan...", "INFO")
        elif button_id == "quick-python-payload":
            status_panel.log_status("Generating Python payload...", "INFO")
            status_panel.update_status("payloads", "1 generated", active=True)
        elif button_id == "quick-ps-payload":
            status_panel.log_status("Generating PowerShell payload...", "INFO")
            status_panel.update_status("payloads", "1 generated", active=True)
        elif button_id == "quick-listener-4444":
            status_panel.log_status("Starting listener on port 4444...", "INFO")
            status_panel.update_status("listener", "Port 4444", active=True)
        elif button_id == "quick-listener-8080":
            status_panel.log_status("Starting listener on port 8080...", "INFO")
            status_panel.update_status("listener", "Port 8080", active=True)
        
        # C2 Framework buttons
        elif button_id == "start-sliver":
            status_panel.log_status("Starting Sliver C2 Framework...", "INFO")
            status_panel.update_status("c2", "Sliver running", active=True)
            
        elif button_id == "start-villain":
            status_panel.log_status("Starting Villain C2 Framework...", "INFO")
            status_panel.update_status("c2", "Villain running", active=True)
            
        elif button_id == "start-hoaxshell":
            status_panel.log_status("Starting HoaxShell C2 Framework...", "INFO")
            status_panel.update_status("c2", "HoaxShell running", active=True)
            
        elif button_id == "stop-framework":
            status_panel.log_status("Stopping C2 framework...", "INFO")
            status_panel.update_status("c2", "Not running", active=False)
            
        # Other buttons
        elif button_id == "generate-payload":
            status_panel.log_status("Generating custom payload...", "INFO")
            
        elif button_id == "run-scan":
            status_panel.log_status("Running vulnerability scan...", "INFO")

# Main function to run the enhanced app
def run_enhanced_app():
    """Run the enhanced RexPloit application"""
    app = RexPloitEnhancedApp()
    app.run()

if __name__ == "__main__":
    run_enhanced_app()