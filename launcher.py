#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RexPloit Launcher - Choose between Original and Enhanced UI
"""

import sys
import os
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

def main():
    console = Console()
    
    # Display banner
    console.print()
    console.print(Panel.fit(
        "[bold blue]RexPloit[/bold blue] - Professional Penetration Testing Framework\n"
        "[yellow]FOR AUTHORIZED SECURITY TESTING ONLY[/yellow]\n"
        "Ensure you have explicit written permission before testing any systems.",
        title="[red]Security Warning[/red]",
        border_style="red"
    ))
    console.print()
    
    # UI Selection
    console.print("[bold green]Choose Your Interface:[/bold green]")
    console.print("1. [cyan]Enhanced UI[/cyan] - Modern three-panel interface with improved layout")
    console.print("2. [yellow]Original UI[/yellow] - Classic interface")
    console.print("3. [red]Exit[/red]")
    console.print()
    
    choice = Prompt.ask("Select interface", choices=["1", "2", "3"], default="1")
    
    if choice == "1":
        console.print("[green]Starting Enhanced UI...[/green]")
        try:
            from enhanced_ui import run_enhanced_app
            run_enhanced_app()
        except ImportError as e:
            console.print(f"[red]Error loading Enhanced UI: {e}[/red]")
            console.print("[yellow]Falling back to Original UI...[/yellow]")
            choice = "2"
    
    if choice == "2":
        console.print("[green]Starting Original UI...[/green]")
        try:
            import rexploit
            rexploit.main()
        except ImportError as e:
            console.print(f"[red]Error loading Original UI: {e}[/red]")
            return 1
    
    elif choice == "3":
        console.print("[yellow]Goodbye![/yellow]")
        return 0
    
    return 0

if __name__ == "__main__":
    sys.exit(main())